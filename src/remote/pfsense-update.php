<?php
$refid = "@@REFID@@";

$cert_str = <<<'CERT'
@@CERTIFICATE@@
CERT;

$key_str = <<<'KEY'
@@PRIVATE_KEY@@
KEY;

require_once("certs.inc");
require_once("pfsense-utils.inc");
require_once("config.inc");
require_once("globals.inc");

// find certificate
foreach ($config['cert'] as &$cert) {
    if ($cert['refid'] === $refid) {
        break;
    }

    unset($cert);
}

if (!isset($cert)) {
    echo "couldn't find certificate with refid $refid.\n";
    die(1);
}

echo "updating certificate \"{$cert['descr']}\" ($refid).\n";
cert_import($cert, $cert_str, $key_str);
write_config("rci: remote update of certificate \"{$cert['descr']}\" ($refid)");

echo "restarting all services used by certificate.\n";
$services = cert_get_all_services($cert['refid']);
cert_restart_services($services);

echo "complete.\n"
?>
