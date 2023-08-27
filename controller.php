<?php

require_once 'vendor/autoload.php';

// load .env
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

// kubernetes client
if (getenv('KUBERNETES_SERVICE_HOST')) {
    $config = KubernetesClient\Config::InClusterConfig();
} else {
    $config = KubernetesClient\Config::BuildConfigFromFile();
}
$kubernetesClient = new KubernetesClient\Client($config);

// configure controller
$controllerName = 'ocsp-manager';
$options = [
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
$controller = new KubernetesController\Controller($controllerName, $kubernetesClient, $options);
$controller->registerPlugin('\OcspManager\Plugin\OcspManager');
$controller->setConfig($config);
$controller->main();
