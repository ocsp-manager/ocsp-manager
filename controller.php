<?php

require_once 'vendor/autoload.php';

use Fig\Http\Message\StatusCodeInterface;
use KubernetesClient\Client;
use KubernetesClient\Config;
use KubernetesClient\Dotty\DotAccess;
use KubernetesController\Controller;
use Psr\Http\Message\ServerRequestInterface;
use React\EventLoop\Loop;
use React\Http\HttpServer;
use React\Http\Message\Response;
use React\Socket\SocketServer;

$cli_options = getopt('', [
    'webhook-only:',
    'webhook-enabled:',
    'listen-tls:',
    'listen-port:',
    'listen-host:',
    'listen-public-cert:',
    'listen-private-key:',
]);
// var_dump($cli_options);
// exit(0);

// load .env
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

// kubernetes client
if (getenv('KUBERNETES_SERVICE_HOST')) {
    $config = Config::InClusterConfig();
} else {
    $config = Config::BuildConfigFromFile();
}
$kubernetesClient = new Client($config);

// configure controller
$controllerName = 'ocsp-manager';
$controller_options = [
    'controllerId' => $controllerName,
    'configMapEnabled' => false,
    'storeEnabled' => false,
];
$config = <<<'EOF'
    enabled: true
    plugins:
      ocsp-manager:
        enabled: true
    EOF;

// run controller
$controller = new Controller($controllerName, $kubernetesClient, $controller_options);
$controller->registerPlugin('\OcspManager\Plugin\OcspManager');
$controller->setConfig($config);
$plugin = $controller->getPluginById('ocsp-manager');

$webhook_enabled = $cli_options['webhook-enabled'] ?? $_ENV['OCSP_MANAGER_WEBHOOK_ENABLED'] ?? true;
if (!is_bool($webhook_enabled)) {
    if (in_array(strtolower($webhook_enabled), ['true', '1', 'yes'], true)) {
        $webhook_enabled = true;
    } else {
        $webhook_enabled = false;
    }
}

/*
 * https://medium.com/ovni/writing-a-very-basic-kubernetes-mutating-admission-webhook-398dbbcb63ec
 * https://github.com/alex-leonhardt/k8s-mutate-webhook/blob/master/deploy/webhook.yaml
 *
 * curl -v 'http://localhost:8080/healthz'
 * curl -k -v 'https://localhost:8443/healthz'
 *
 * curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' -v 'http://localhost:8080/webhook' -k
 * curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' -v 'https://localhost:8443/webhook' -k
 */
if ($webhook_enabled) {
    // need this to support mutating webhook to secrets are present at the moment a secret is created
    // https://reactphp.org/http/
    $http = new HttpServer(function (ServerRequestInterface $request) use ($controller, $plugin) {
        $controller->log("mutating webhook http {$request->getMethod()} {$request->getUri()}");
        //        return React\Http\Message\Response::plaintext(
        //            "Hello World!\n"
        //        );

        switch ($request->getRequestTarget()) {
            case '/healthz':
                return match ($request->getMethod()) {
                    'GET' => Response::json(['success' => true])->withStatus(StatusCodeInterface::STATUS_OK),
                    default => Response::json(['error' => 'not found'])->withStatus(StatusCodeInterface::STATUS_NOT_FOUND),
                };

            case '/webhook':
                switch ($request->getMethod()) {
                    case 'POST':
                        // must be json
                        if ('application/json' !== $request->getHeaderLine('Content-Type')) {
                            return Response::json(
                                ['error' => 'Only supports application/json']
                            )->withStatus(StatusCodeInterface::STATUS_UNSUPPORTED_MEDIA_TYPE);
                        }

                        // must be sent valid json
                        $input = json_decode($request->getBody()->getContents(), true);
                        if (JSON_ERROR_NONE !== json_last_error()) {
                            return Response::json(
                                ['error' => 'invalid JSON data given']
                            )->withStatus(StatusCodeInterface::STATUS_BAD_REQUEST);
                        }
                        // $controller->log(json_encode($input));

                        $operation = DotAccess::get($input, 'request.operation');
                        // $controller->log($operation);
                        if ('create' !== strtolower($operation)) {
                            return Response::json(
                                ['error' => 'invalid operation given: '.$operation.' must be CREATE']
                            )->withStatus(StatusCodeInterface::STATUS_BAD_REQUEST);
                        }

                        $secret = DotAccess::get($input, 'request.object');
                        // $controller->log(json_encode($secret));

                        $res = [
                            'apiVersion' => 'admission.k8s.io/v1',
                            'kind' => 'AdmissionReview',
                            'response' => [
                                'uid' => DotAccess::get($input, 'request.uid'),
                                'allowed' => true,
                            ],
                        ];

                        // return immediately
                        $shouldProcess = $plugin->webhookShouldProcessSecret($secret);
                        if (!$shouldProcess) {
                            return Response::json(
                                $res
                            );
                        }
                        // https://dev.to/yuelirex/practical-example-of-using-a-mutating-admission-webhook-5ff8
                        // https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#webhook-request-and-response

                        // should return a json patch
                        // [
                        //  { "op": "replace", "path": "/message", "value": "Patching JSON is fun" },
                        //  { "op": "add", "path": "/with", "value": "jsonpatch.me" },
                        //  { "op": "remove", "path": "/from" }
                        // ]

                        // {
                        //      "apiVersion": "admission.k8s.io/v1",
                        //      "kind": "AdmissionReview",
                        //      "response": {
                        //        "uid": "<value from request.uid>",
                        //        "allowed": true,
                        //        "patchType": "JSONPatch",
                        //        "patch": "W3sib3AiOiAiYWRkIiwgInBhdGgiOiAiL3NwZWMvcmVwbGljYXMiLCAidmFsdWUiOiAzfV0="
                        //      }
                        // }

                        try {
                            $ocsp = $plugin->handleSecret($secret, true);
                            if (!empty($ocsp)) {
                                $res['response']['patchType'] = 'JSONPatch';
                                $patch = $plugin->getWebhookPatch($secret, $ocsp);
                                // $controller->log("mutating webhook http patch: " . json_encode($patch));
                                $res['response']['patch'] = base64_encode(json_encode($patch));
                            }

                            return Response::json(
                                $res
                            );
                        } catch (Exception $e) {
                            $controller->log('mutating webhook failed to generate patch error: '.$e->getMessage());

                            return Response::json(
                                $res
                            );
                        }

                    default:
                        return Response::json(['error' => 'not found'])->withStatus(StatusCodeInterface::STATUS_NOT_FOUND);
                }

                // no break
            default:
                return Response::json(['error' => 'not found'])->withStatus(StatusCodeInterface::STATUS_NOT_FOUND);
        }

        //        if (!isset($input->name) || !is_string($input->name)) {
        //            return Response::json(
        //                array('error' => 'JSON data does not contain a string "name" property')
        //            )->withStatus(Response::STATUS_UNPROCESSABLE_ENTITY);
        //        }
    });

    $listen_tls = $cli_options['listen-tls'] ?? $_ENV['OCSP_MANAGER_LISTEN_TLS'] ?? 'false';
    if (in_array(strtolower($listen_tls), ['true', '1', 'yes'])) {
        $listen_tls = true;
    } else {
        $listen_tls = false;
    }

    $listen_cert_provided = $cli_options['listen-public-cert'] ?? $_ENV['OCSP_MANAGER_LISTEN_PUBLIC_CERT'] ?? false;
    $listen_cert = $cli_options['listen-public-cert'] ?? $_ENV['OCSP_MANAGER_LISTEN_PUBLIC_CERT'] ?? 'tls.crt';
    $listen_key = $cli_options['listen-private-key'] ?? $_ENV['OCSP_MANAGER_LISTEN_PRIVATE_KEY'] ?? 'tls.key';

    // force tls on if cert explicitly provided
    if ($listen_cert_provided) {
        $listen_tls = true;
    }

    $default_listen_port = $listen_tls ? '8443' : '8080';
    $listen_protocol = $listen_tls ? 'tls' : 'tcp';

    $listen_host = $cli_options['listen-host'] ?? $_ENV['OCSP_MANAGER_LISTEN_HOST'] ?? '0.0.0.0';
    $listen_port = $cli_options['listen-port'] ?? $_ENV['OCSP_MANAGER_LISTEN_PORT'] ?? $default_listen_port;

    $socket_options = [];
    if ($listen_tls) {
        if (!file_exists($listen_cert)) {
            $controller->log('webhook cert is missing '.$listen_cert);

            exit(1);
        }

        if (!file_exists($listen_key)) {
            $controller->log('webhook key is missing '.$listen_key);

            exit(1);
        }

        $socket_options = ['tls' => [
            'local_cert' => $listen_cert,
            'local_pk' => $listen_key,
            // 'local_cert' => __DIR__ . '/localhost.pem'
        ]];
    }

    $webhook_listener = "{$listen_protocol}://{$listen_host}:{$listen_port}";
    $socket = new SocketServer($webhook_listener, $socket_options);
    $http->listen($socket);
    $socket->on('error', function (Exception $e) use ($controller) {
        $controller->log('mutating webhook socket error '.$e->getMessage());
    });
    $socket->on('close', function () use ($controller) {
        $controller->log('mutating webhook socket closed');

        exit(1);
    });

    $controller->log('mutating webhook listening on '.str_replace(['tls:', 'tcp:'], ['https:', 'http:'], $socket->getAddress()));

    $webhook_only = $cli_options['webhook-only'] ?? $_ENV['OCSP_MANAGER_WEBHOOK_ONLY'] ?? false;
    if (!is_bool($webhook_only)) {
        if (in_array(strtolower($webhook_only), ['true', '1', 'yes'], true)) {
            $webhook_only = true;
        } else {
            $webhook_only = false;
        }
    }

    if ($webhook_only) {
        // explicitly invoking run is a blocking operation and prevents shutdown operations from running unwanted
        // only needed if something else is not maintaining an event loop (ie: ->main() below
        Loop::run();
    }
}

$controller->main();
