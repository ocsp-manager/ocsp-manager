<?php

namespace OcspManager\Plugin;

use cash\LRUCache;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use KubernetesClient\Dotty\DotAccess;
use KubernetesController\Plugin\AbstractPlugin;
use Ocsp\CertificateInfo;
use Ocsp\CertificateLoader;
use Ocsp\Exception\Asn1DecodingException;
use Ocsp\Exception\RequestException;
use Ocsp\Ocsp;
use OcspManager\Constants;
use OcspManager\Utils;
use Psr\Http\Message\StreamInterface;

/**
 * TODO: use threads to handle http requests concurrently - https://www.sitepoint.com/parallel-programming-pthreads-php-fundamentals/.
 *
 * https://github.com/mlocati/ocsp
 * https://github.com/travisghansen/kubernetes-client-php
 */
class OcspManager extends AbstractPlugin
{
    public const PLUGIN_ID = 'ocsp-manager';

    private LRUCache $issuerCertsLRU;

    private Client $httpClient;

    private Ocsp $ocsp;

    private CertificateLoader $certificateLoader;

    private CertificateInfo $certificateInfo;

    private int $lastAllProcessedTime;

    private array $secretList;

    public function init()
    {
        $this->issuerCertsLRU = new LRUCache(500);
        $this->httpClient = new Client([
            'timeout' => 2.0,
        ]);

        $this->certificateLoader = new CertificateLoader();
        $this->certificateInfo = new CertificateInfo();
        $this->ocsp = new Ocsp();

        $controller = $this->getController();

        $secrets = $this->getAllSecretList();

        // initial load of secrets
        $endpoint = '/api/v1/secrets';
        // limit=500
        $params = $this->getSecretFilterParams();
        // watch for secret changes
        $params['watch'] = 'true';
        $params['resourceVersion'] = $secrets['metadata']['resourceVersion'];
        $watch = $controller->getKubernetesClient()->createWatch($endpoint, $params, $this->getSecretWatchCallback());
        $this->addWatch($watch);
    }

    public function deinit() {}

    public function preReadWatches() {}

    public function postReadWatches()
    {
        // every 12 hours by default
        $reconcile = $_ENV['OCSP_MANAGER_RECONCILE_INTERVAL'] ?? $_ENV['OCSP_MANAGER_RECONCILE_INTERVAL'] ?? 60 * 60 * 12;
        $now = time();
        if (empty($this->lastAllProcessedTime) || $now > ($this->lastAllProcessedTime + $reconcile)) {
            $this->log('reconcile interval passed, performing full reconciliation');
            $secrets = $this->getAllSecretList();
            $this->processAllSecrets($secrets);
        }
    }

    public function doAction()
    {
        return true;
    }

    /**
     * This attempts to replicate the filtering logic used in the watches/list http calls because such filtering is not yet possible to set on the mutatingwebhook configuratino.
     *
     * @param mixed $secret
     *
     * @return bool
     *
     * @throws \Exception
     */
    public function webhookShouldProcessSecret($secret)
    {
        $secretPath = "{$secret['metadata']['namespace']}/{$secret['metadata']['name']}";
        $key = ['data', $this->getResponseSecretKey($secret)];
        if (DotAccess::exists($secret, $key)) {
            $this->getController()->log("webhook ignoring cert {$secretPath} because ocsp data is already present");

            return false;
        }

        $params = $this->getSecretFilterParams();

        // note, *ALL* selectors in the comma-separated list must be present/equal
        if ($params['labelSelector']) {
            foreach (explode(',', $params['labelSelector']) as $selector) {
                $parts = explode('=', $selector, 2);
                if (DotAccess::get($secret, ['metadata', 'labels', $parts[0]], null) != $parts[1]) {
                    $this->getController()->log("webhook ignoring cert {$secretPath} due to failed labelSelector assertion: ".$selector);

                    return false;
                }
            }
        }

        // note, *ALL* selectors in the comma-separated list must be present/equal
        if ($params['fieldSelector']) {
            foreach (explode(',', $params['fieldSelector']) as $selector) {
                $parts = explode('=', $selector, 2);
                if (DotAccess::get($secret, $parts[0], null) != $parts[1]) {
                    $this->getController()->log("webhook ignoring cert {$secretPath} due to failed fieldSelector assertion: ".$selector);

                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Reconcile the secret to add/remove OCSP data as appropriate.
     *
     * In order to fetch ocsp data you need:
     * - a certificate
     * - an OCSP responder URL/endpoint
     * - the CA cert corresponding to the certificate
     *
     * The OCSP responder URL is often embedded into the certificate, if not it can be set via annotation.
     * The CA cert can be pulled from (in order of preference):
     * - URL in the `ca-url` annotation
     * - `ca.crt` if present in the secret
     * - `tls.crt` if it has a full certificate chain
     * - CA URL embedded in the cert if present
     *
     * @param mixed $secret
     * @param mixed $webhookMode
     */
    public function handleSecret($secret, $webhookMode = false)
    {
        $secretPath = "{$secret['metadata']['namespace']}/{$secret['metadata']['name']}";
        $this->log("handling secret: {$secretPath}");

        // ignore secrets without a crt
        if (!isset($secret['data']['tls.crt'])) {
            $this->log("ignoring secret missing tls.crt: {$secretPath}");

            return;
        }

        if (isset($secret['metadata']['annotations']['reflector.v1.k8s.emberstack.com/reflects'])) {
            $this->log("ignoring reflected secret: {$secretPath}");

            return;
        }

        //        $this->log("secret details: " . json_encode($secret));
        //        return;

        $response_key = $this->getResponseSecretKey($secret);

        // get crt
        $crt_chain_data = base64_decode($secret['data']['tls.crt']);
        $crts = Utils::splitCertificateChain($crt_chain_data);
        $crt_data = $crts[0];

        if (empty($crt_data)) {
            $this->log("crt data empty: {$secretPath}");

            return;
        }

        // attempt to get CA data with k8s data
        $cacrt_data = null;

        $annotationCAURL = Utils::getOcspManagerSecretAnnotationValue($secret, 'ca-url');
        if (empty($cacrt_data) && !empty($annotationCAURL)) {
            $cacrt_data = (string) $this->fetchIssuerCertByURL($annotationCAURL);
            // normalize to PEM
            $cacrt_data = Utils::der2pem($cacrt_data);

            if (!empty($cacrt_data)) {
                $this->log("discovered CA using annotation URL: {$secretPath}");
            }
        }

        if (empty($cacrt_data)) {
            if (isset($secret['data']['ca.crt'])) {
                $this->log("discovered CA in ca.crt key in secret: {$secretPath}");
                $cacrt_data = base64_decode($secret['data']['ca.crt']);
            }
        }

        if (empty($cacrt_data)) {
            if (!empty($crts[1])) {
                // TODO: this may require additional logic, relevant CA may be the last entry for example
                $cacrt_data = $crts[1];
            }
            if (!empty($cacrt_data)) {
                $this->log("discovered CA in tls.crt chain: {$secretPath}");
            }
        }

        try {
            // parse crt_data
            $certificate = $this->certificateLoader->fromString($crt_data);
            $certificateX509Info = openssl_x509_parse($crt_data);
            // https://stackoverflow.com/questions/9621792/convert-a-big-integer-to-a-full-string-in-php
            // $certificateSerialNumber = printf('%0.0f', hexdec($certificateX509Info['serialNumber']));
            $certificateSerialNumber = Utils::extractSerialNumber($certificate);
            $this->log("successfully loaded certificate: {$secretPath} {$certificateSerialNumber} {$certificateX509Info['name']}");

            // check existing ocsp response
            if (isset($secret['data'][$response_key])) {
                try {
                    $currentOCSPRawResponse = base64_decode($secret['data'][$response_key]);
                    $currentOCSPResponse = $this->ocsp->decodeOcspResponseSingle((string) $currentOCSPRawResponse);
                    // this is the serial number of the cert being checked
                    $currentOCSPResponseSerialNumber = $currentOCSPResponse->getCertificateSerialNumber();
                    if ($currentOCSPResponseSerialNumber != $certificateSerialNumber) {
                        $this->log("OCSP response serial mismatch, removing OCSP data: {$secretPath}");

                        try {
                            $this->setSecretOCSPResponse($secret, null);
                        } catch (\Exception $e) {
                            $this->log("failed to remove OCSP data: {$secretPath} {$e->getMessage()}");
                        }
                    }

                    /**
                     * https://letsencrypt.org/documents/isrg-cp-v3.0/#4.9.10-on-line-revocation-checking-requirements
                     * https://serverfault.com/questions/985493/next-update-is-missing-from-the-ocsp-response.
                     *
                     * If nextUpdate is not set, the responder is indicating that newer revocation information is available all the time.
                     *
                     * In practice, nextUpdate is considered the expiration time of the OCSP response. In the case of
                     * letsencrypt the responses are issued with a validity interval of 7 days and new data is available
                     * every 3 days.
                     *
                     * You should refresh the data every ish floor((Validity / 2) - 1)
                     *
                     * openssl ocsp -issuer chain.pem -cert wikipedia.pem -url http://ocsp.digicert.com
                     * wikipedia.pem: good
                     *   This Update: Apr  9 08:45:00 2014 GMT
                     *   Next Update: Apr 16 09:00:00 2014 GMT
                     */
                    $thisUpdate = $currentOCSPResponse->getThisUpdate();
                    $thisUpdateTimestamp = $thisUpdate->getTimestamp();
                    $now = time();

                    // Normally this should be floor((nextUpdate - thisUpdate / 2) 1) but often nextUpdate is not present
                    $refresh = $this->getRefreshInterval($secret);
                    if ($now > ($thisUpdateTimestamp + $refresh) || $currentOCSPResponseSerialNumber != $certificateSerialNumber) {
                        $this->log("OCSP data is considered stale, attempting a refresh: {$secretPath}");
                    } else {
                        $this->log("OCSP data is considered fresh, ignoring update: {$secretPath}");

                        return;
                    }
                } catch (\Exception $e) {
                    $this->log("failed to grok existing ocsp data: {$e->getMessage()}");
                }
            }

            // search for OCSP URL
            $ocspURL = null;
            if (empty($ocspURL)) {
                $ocspURL = Utils::getOcspManagerSecretAnnotationValue($secret, 'ocsp-responder-url');
                if ($ocspURL) {
                    $this->log("determined OCSP responder URL from annotation: {$secretPath}");
                }
            }

            if (empty($ocspURL)) {
                $ocspURL = $this->certificateInfo->extractOcspResponderUrl($certificate);
                if ($ocspURL) {
                    $this->log("determined OCSP responder URL from certificate: {$secretPath}");
                }
            }

            if (empty($ocspURL)) {
                $this->log("failed to determine OCSP responder URL: {$secretPath}");

                return;
            }

            $this->log("discovered OCSP URL: {$ocspURL} for {$secretPath}");

            // force it to empty for testing purposes
            // $cacrt_data = null;

            // attempt to fetch CA data if not already present
            if (empty($cacrt_data)) {
                $urlOfIssuerCertificate = $this->certificateInfo->extractIssuerCertificateUrl($certificate);
                if ($urlOfIssuerCertificate) {
                    $cacrt_data = (string) $this->fetchIssuerCertByURL($urlOfIssuerCertificate);
                    // normalize to PEM
                    $cacrt_data = Utils::der2pem($cacrt_data);
                }

                if (!empty($cacrt_data)) {
                    $this->log("discovered CA using issuer URL: {$secretPath}");
                }
            }

            // if CA data is not available return, otherwise parse
            $issuerCertificate = null;
            if ($cacrt_data) {
                $issuerCertificate = $this->certificateLoader->fromString($cacrt_data);
                $issuerCertificateX509Info = openssl_x509_parse($cacrt_data);
                $issuerCertificateSerialNumber = Utils::extractSerialNumber($issuerCertificate);
                $this->log("successfully loaded CA: {$secretPath} {$issuerCertificateSerialNumber} {$issuerCertificateX509Info['name']}");
            } else {
                $this->log("failed CA discovery: {$secretPath}");

                return;
            }

            // TODO: produce k8s event here in a try/catch if we fail to fetch the ocsp data and/or save it

            $rawOCSPResponse = $this->fetchOCSPResponse($ocspURL, $certificate, $issuerCertificate);
            // TODO: do not really care what the response is, needs to get written regardless of status etc
            // $ocspResponse = $this->ocsp->decodeOcspResponseSingle((string) $rawOCSPResponse);

            $this->log("successfully fetched OCSP data: {$secretPath}");
            if ($webhookMode) {
                return $rawOCSPResponse;
            }
            $this->setSecretOCSPResponse($secret, $rawOCSPResponse);
            $this->log("successfully updated secret with OCSP data: {$secretPath}");
        } catch (\Exception $e) {
            $this->log("failed to fetch OCSP data {$secretPath}: {$e->getMessage()}");
        }
    }

    public function getWebhookPatch($secret, $ocsp)
    {
        return $this->setSecretOCSPResponse($secret, $ocsp, true);
    }

    private function getSecretFilterParams(): array
    {
        $labelSelector = $_ENV['OCSP_MANAGER_SECRET_LABEL_SELECTOR'] ?? $_ENV['OCSP_MANAGER_SECRET_LABEL_SELECTOR'] ?? null;
        $fieldSelector = $_ENV['OCSP_MANAGER_SECRET_FIELD_SELECTOR'] ?? $_ENV['OCSP_MANAGER_SECRET_FIELD_SELECTOR'] ?? 'type=kubernetes.io/tls';

        return [
            'labelSelector' => $labelSelector,
            'fieldSelector' => $fieldSelector,
        ];
    }

    private function processAllSecrets($secrets)
    {
        if (empty($secrets)) {
            $this->log('processing 0 secrets');

            return;
        }
        $secretCount = count($secrets['items']);
        $this->log("processing {$secretCount} secrets");
        foreach ($secrets['items'] as $secret) {
            $this->handleSecret($secret);
        }
        $this->lastAllProcessedTime = time();
    }

    private function getAllSecretList()
    {
        $endpoint = '/api/v1/secrets';
        $params = $this->getSecretFilterParams();
        $secretList = $this->getController()->getKubernetesClient()->createList($endpoint, $params);
        $result = $secretList->get();
        if ('Status' == $result['kind']) {
            $message = "failed to fetch secrets: {$result['status']} {$result['reason']} ({$result['code']}) {$result['message']}";

            throw new \Exception($message);
        }

        return $result;
    }

    private function getSecretWatchCallback()
    {
        return function ($event, $watch) {
            $this->logEvent($event);

            switch ($event['type']) {
                case 'ADDED':
                case 'MODIFIED':
                    $this->handleSecret($event['object']);
                    $this->delayedAction();

                    break;

                case 'DELETED':
                    // TODO: remove ocsp-manager data(?) from secret (if the secret still exists and is just removed from selectors)
                    break;
            }
        };
    }

    /**
     * Get the key name to be used in the secret to store the OCSP data/response.
     *
     * @param mixed $secret
     *
     * @return null|mixed|string
     */
    private function getResponseSecretKey($secret): string
    {
        $key = Utils::getOcspManagerSecretAnnotationValue($secret, 'response-key');
        if (!$key) {
            $key = $_ENV['OCSP_MANAGER_DEFAULT_RESPONSE_SECRET_KEY'] ?? $_ENV['OCSP_MANAGER_DEFAULT_RESPONSE_SECRET_KEY'] ?? Constants::DEFAULT_RESPONSE_SECRET_KEY;
        }

        return $key;
    }

    /**
     * Get cert data (DER) from URL.
     *
     * @param mixed $url
     *
     * @return mixed|string
     *
     * @throws GuzzleException
     */
    private function fetchIssuerCertByURL($url): mixed
    {
        $cache_value = $this->issuerCertsLRU->get($url);
        if ($cache_value && !empty($cache_value['crt'])) {
            return $cache_value['crt'];
        }

        $this->log("fetching CA from issuer URL: {$url}");
        $response = $this->httpClient->get($url);
        $cacrt = (string) $response->getBody();
        $this->issuerCertsLRU->put($url, ['crt' => $cacrt, 'created_at' => time()]);

        return $cacrt;
    }

    /**
     * Get OCSP data.
     *
     * @param mixed $ocspURL
     * @param mixed $certificate
     * @param mixed $issuerCertificate
     *
     * @throws GuzzleException
     * @throws RequestException
     */
    private function fetchOCSPResponse($ocspURL, $certificate, $issuerCertificate): StreamInterface
    {
        // Extract the relevant data from the two certificates
        $ocspRequestInfo = $this->certificateInfo->extractRequestInfo($certificate, $issuerCertificate);

        // Build the raw body (der binary) to be sent to the OCSP Responder URL
        $ocspRequestBody = $this->ocsp->buildOcspRequestBodySingle($ocspRequestInfo);
        $response = $this->httpClient->request('POST', $ocspURL, [
            'headers' => [
                'Content-Type' => Ocsp::OCSP_REQUEST_MEDIATYPE,
            ],
            'body' => $ocspRequestBody,
        ]);

        $code = $response->getStatusCode();
        if (200 !== $code) {
            throw new \RuntimeException("failed to fetch OCSP response non-200 response code: {$code}");
        }

        $contentType = $response->getHeader('content-type')[0];
        if (Ocsp::OCSP_RESPONSE_MEDIATYPE !== $contentType) {
            throw new \RuntimeException('Whoops, the Content-Type header of the response seems wrong!');
        }

        // TODO: perhaps need to support storing a multi-response value
        // $responses = $ocsp->decodeOcspResponse($body));
        return $response->getBody();
    }

    /**
     * @param mixed $secret
     * @param mixed $ocsp
     * @param mixed $webhookMode
     *
     * @return null|array|void
     *
     * @throws Asn1DecodingException
     */
    private function setSecretOCSPResponse($secret, $ocsp, $webhookMode = false)
    {
        $secretPath = "{$secret['metadata']['namespace']}/{$secret['metadata']['name']}";
        $client = $this->getController()->getKubernetesClient();

        if (empty($ocsp)) {
            // TODO: make this optional?
            $this->removeSecretOCSPResponse($secret);

            return;
        }

        $ocspResponse = $this->ocsp->decodeOcspResponseSingle((string) $ocsp);
        $thisUpdate = $ocspResponse->getThisUpdate();
        $nextUpdate = $ocspResponse->getNextUpdate();

        $response_key = $this->getResponseSecretKey($secret);
        $response_fetch_time = Utils::dateTo8601Zulu(new \DateTime());
        $this_update_time = Utils::dateTo8601Zulu($thisUpdate);
        $next_update_time = '';
        if ($nextUpdate) {
            $next_update_time = Utils::dateTo8601Zulu($nextUpdate);
        }

        $ocsp_revoked_reason = null;
        $ocsp_revoked_time = null;
        if ($ocspResponse->isRevoked()) {
            $ocsp_revoked_reason = (string) Utils::getRevokedReasonFromCode($ocspResponse->getRevocationReason());
            $ocsp_revoked_time = Utils::dateTo8601Zulu($ocspResponse->getRevokedOn());
        }

        $fetched_ocsp_data = base64_encode((string) $ocsp);
        // patch data
        $data = [
            'kind' => 'Secret',
            'metadata' => [
                'name' => $secret['metadata']['name'],
                // setting annotation value to null will remove the annotation in kubernetes
                'annotations' => [
                    Constants::ANNOTATION_PREFIX.'/response-fetch-time' => $response_fetch_time,
                    Constants::ANNOTATION_PREFIX.'/ocsp-this-update' => $this_update_time,
                    Constants::ANNOTATION_PREFIX.'/ocsp-next-update' => $next_update_time,
                    Constants::ANNOTATION_PREFIX.'/ocsp-revoked-time' => $ocsp_revoked_time,
                ],
                'labels' => [
                    Constants::ANNOTATION_PREFIX.'/ocsp-is-revoked' => $ocspResponse->isRevoked() ? 'true' : 'false',
                    Constants::ANNOTATION_PREFIX.'/ocsp-revoked-reason' => $ocsp_revoked_reason,
                    Constants::ANNOTATION_PREFIX.'/cert-serial-number' => $ocspResponse->getCertificateSerialNumber(),
                ],
            ],
            'data' => [
                $response_key => $fetched_ocsp_data,
            ],
        ];

        // JSONPatch formatting
        // NOTE: a null value will be set to "" in the k8s api (ie: field will exist with a value of empty string)
        // NOTE: add OR replace ops will both work (ie: replace will succeed even if the field is not previously present)
        if ($webhookMode) {
            return [
                // annotations
                ['op' => 'add', 'path' => '/metadata/annotations/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/response-fetch-time'), 'value' => $response_fetch_time],
                ['op' => 'add', 'path' => '/metadata/annotations/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/ocsp-this-update'), 'value' => $this_update_time],
                ['op' => 'add', 'path' => '/metadata/annotations/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/ocsp-next-update'), 'value' => $next_update_time],
                ['op' => 'add', 'path' => '/metadata/annotations/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/ocsp-revoked-time'), 'value' => $ocsp_revoked_time],

                // labels
                ['op' => 'add', 'path' => '/metadata/labels/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/ocsp-is-revoked'), 'value' => $ocspResponse->isRevoked() ? 'true' : 'false'],
                ['op' => 'add', 'path' => '/metadata/labels/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/ocsp-revoked-reason'), 'value' => $ocsp_revoked_reason],
                ['op' => 'add', 'path' => '/metadata/labels/'.Utils::jsonPatchEncodePathSegment(Constants::ANNOTATION_PREFIX.'/cert-serial-number'), 'value' => $ocspResponse->getCertificateSerialNumber()],

                // ocsp
                ['op' => 'add', 'path' => '/data/'.Utils::jsonPatchEncodePathSegment($response_key), 'value' => $fetched_ocsp_data],
            ];
        }

        if (isset($secret['data'][$response_key]) && $secret['data'][$response_key] == $fetched_ocsp_data) {
            $this->log("OCSP data already current, you should consider modifying the refresh-interval, ignoring update: {$secretPath}");

            return;
        }

        $endpoint = Utils::getSecretApiEndpoint($secret);
        $client->request($endpoint, 'PATCH', [], $data);
    }

    /**
     * Clear out all ocsp-manager related data from the secret.
     *
     * @param mixed $secret
     *
     * @throws \Exception
     */
    private function removeSecretOCSPResponse($secret): void
    {
        $client = $this->getController()->getKubernetesClient();
        $response_key = $this->getResponseSecretKey($secret);

        $data = [
            'kind' => 'Secret',
            'metadata' => [
                'name' => $secret['metadata']['name'],
                'annotations' => [],
                'labels' => [],
            ],
            'data' => [
                $response_key => null,
            ],
        ];

        // remove any written annotations
        $annotations = [
            Constants::ANNOTATION_PREFIX.'/response-fetch-time',
            Constants::ANNOTATION_PREFIX.'/ocsp-this-update',
            Constants::ANNOTATION_PREFIX.'/ocsp-revoked-time',
        ];
        foreach ($annotations as $annotation) {
            $data['metadata']['annotations'][$annotation] = null;
        }

        // remove any written labels
        $labels = [
            Constants::ANNOTATION_PREFIX.'/ocsp-is-revoked',
            Constants::ANNOTATION_PREFIX.'/ocsp-revoked-reason',
        ];
        foreach ($labels as $label) {
            $data['metadata']['labels'][$label] = null;
        }

        $endpoint = Utils::getSecretApiEndpoint($secret);
        $client->request($endpoint, 'PATCH', [], $data);
    }

    /**
     * Remove *only* the data portion of the OCSP response from the secret.
     *
     * @param mixed $secret
     *
     * @throws \Exception
     */
    private function removeSecretOCSPResponseData($secret): void
    {
        $secretPath = "{$secret['metadata']['namespace']}/{$secret['metadata']['name']}";
        $client = $this->getController()->getKubernetesClient();
        $response_key = $this->getResponseSecretKey($secret);

        // patch data
        $data = [
            [
                'op' => 'remove',
                'path' => '/data/'.Utils::jsonPatchEncodePathSegment($response_key),
            ],
        ];

        $endpoint = Utils::getSecretApiEndpoint($secret);
        $response = $client->request($endpoint, 'PATCH-JSON', [], $data);
        if ('Status' == $response['kind'] && 'Failure' == $response['status']) {
            throw new \RuntimeException("failed to remove OCSP data from secret: {$secretPath} {$response['message']}");
        }
    }

    /**
     * Get the refresh interval for the secret.
     *
     * @param mixed $secret
     */
    private function getRefreshInterval($secret): int
    {
        $interval = Utils::getOcspManagerSecretAnnotationValue($secret, 'refresh-interval');
        if (!empty($interval)) {
            return (int) $interval;
        }

        // nginx-ingress default, works well with letsencrypt's 7 day validity
        $interval = $_ENV['OCSP_MANAGER_REFRESH_INTERVAL'] ?? $_ENV['OCSP_MANAGER_REFRESH_INTERVAL'] ?? 3600 * 24 * 3;

        return (int) $interval;
    }
}
