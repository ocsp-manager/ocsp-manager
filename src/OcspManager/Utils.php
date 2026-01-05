<?php

namespace OcspManager;

use Ocsp\Asn1\Element\Sequence;
use Ocsp\Asn1\UniversalTagID;
use Ocsp\Response;

class Utils
{
    public static function getSecretApiEndpoint($secret)
    {
        return "/api/v1/namespaces/{$secret['metadata']['namespace']}/secrets/{$secret['metadata']['name']}";
    }

    public static function der2pem($der_data, $type = 'CERTIFICATE')
    {
        $pem = chunk_split(base64_encode($der_data), 64, "\n");

        return '-----BEGIN '.$type."-----\n".$pem.'-----END '.$type."-----\n";
    }

    public static function splitCertificateChain($crt)
    {
        $split = '-----BEGIN CERTIFICATE-----';
        $crts = explode($split, $crt);
        array_walk($crts, function (&$item, $index) use ($split) {
            if (empty($item)) {
                return;
            }
            $item = $split.$item;
        });

        return array_values(array_filter($crts));
    }

    public static function extractSerialNumber(Sequence $certificate)
    {
        $tbsCertificate = $certificate->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if (null === $tbsCertificate) {
            return '';
        }
        $serialNumber = $tbsCertificate->getFirstChildOfType(UniversalTagID::INTEGER);
        if (null === $serialNumber) {
            return '';
        }

        return (string) $serialNumber->getValue();
    }

    public static function getOcspManagerSecretAnnotationValue($secret, $key)
    {
        return $secret['metadata']['annotations'][Constants::ANNOTATION_PREFIX.'/'.$key] ?? $secret['metadata']['annotations'][Constants::ANNOTATION_PREFIX.'/'.$key] ?? null;
    }

    public static function dateTo8601Zulu(\DateTimeInterface $date): string
    {
        return (clone $date)
            ->setTimezone(new \DateTimeZone('UTC'))
            ->format('Y-m-d\TH:i:s\Z')
        ;
    }

    public static function jsonPatchEncodePathSegment($segment)
    {
        return str_replace('/', '~1', $segment);
    }

    public static function getRevokedReasonFromCode($id): string
    {
        return match ($id) {
            Response::REVOCATIONREASON_UNSPECIFIED => 'UNSPECIFIED',
            Response::REVOCATIONREASON_KEYCOMPROMISE => 'KEYCOMPROMISE',
            Response::REVOCATIONREASON_CACOMPROMISE => 'CACOMPROMISE',
            Response::REVOCATIONREASON_AFFILIATIONCHANGED => 'AFFILIATIONCHANGED',
            Response::REVOCATIONREASON_SUPERSEDED => 'SUPERSEDED',
            Response::REVOCATIONREASON_CESSATIONOFOPERATION => 'CESSATIONOFOPERATION',
            Response::REVOCATIONREASON_CERTIFICATEHOLD => 'CERTIFICATEHOLD',
            Response::REVOCATIONREASON_REMOVEFROMCRL => 'REMOVEFROMCRL',
            Response::REVOCATIONREASON_PRIVILEGEWITHDRAWN => 'PRIVILEGEWITHDRAWN',
            Response::REVOCATIONREASON_AACOMPROMISE => 'AACOMPROMISE',
            default => "UNKNOWN ID: {$id}",
        };
    }
}
