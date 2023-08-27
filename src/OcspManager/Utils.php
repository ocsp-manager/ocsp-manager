<?php

namespace OcspManager;

use Ocsp\Asn1\UniversalTagID;

class Utils
{
    public static function der2pem($der_data, $type = 'CERTIFICATE')
    {
        $pem = chunk_split(base64_encode($der_data), 64, "\n");
        $pem = '-----BEGIN '.$type."-----\n".$pem.'-----END '.$type."-----\n";

        return $pem;
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

    public static function extractSerialNumber(\Ocsp\Asn1\Element\Sequence $certificate)
    {
        $tbsCertificate = $certificate->getFirstChildOfType(UniversalTagID::SEQUENCE);
        if ($tbsCertificate === null) {
            return '';
        }
        $serialNumber = $tbsCertificate->getFirstChildOfType(UniversalTagID::INTEGER);
        if ($serialNumber === null) {
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
            ->format('Y-m-d\TH:i:s\Z');
    }

    public static function getRevokedReasonFromCode($id): string
    {
        return match ($id) {
            \Ocsp\Response::REVOCATIONREASON_UNSPECIFIED => 'UNSPECIFIED',
            \Ocsp\Response::REVOCATIONREASON_KEYCOMPROMISE => 'KEYCOMPROMISE',
            \Ocsp\Response::REVOCATIONREASON_CACOMPROMISE => 'CACOMPROMISE',
            \Ocsp\Response::REVOCATIONREASON_AFFILIATIONCHANGED => 'AFFILIATIONCHANGED',
            \Ocsp\Response::REVOCATIONREASON_SUPERSEDED => 'SUPERSEDED',
            \Ocsp\Response::REVOCATIONREASON_CESSATIONOFOPERATION => 'CESSATIONOFOPERATION',
            \Ocsp\Response::REVOCATIONREASON_CERTIFICATEHOLD => 'CERTIFICATEHOLD',
            \Ocsp\Response::REVOCATIONREASON_REMOVEFROMCRL => 'REMOVEFROMCRL',
            \Ocsp\Response::REVOCATIONREASON_PRIVILEGEWITHDRAWN => 'PRIVILEGEWITHDRAWN',
            \Ocsp\Response::REVOCATIONREASON_AACOMPROMISE => 'AACOMPROMISE',
            default => "UNKNOWN ID: {$id}",
        };
    }
}
