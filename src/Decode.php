<?php
declare(strict_types=1);

namespace Wumvi\Sign;

use Wumvi\Sign\Model\Sign as SignModel;
use Wumvi\Sign\Model\SignWithData;

class Decode
{
    public static function decodeSign(string $rawData): ?SignModel
    {
        $algo = substr($rawData, 0, Encode::ALGO_PREFIX_LEN) ?: '';
        if (!array_key_exists($algo, Encode::ALGO_NAME)) {
            return null;
        }

        $saltName = substr($rawData, Encode::ALGO_PREFIX_LEN, Encode::SALT_NAME_LEN);
        if (empty($saltName)) {
            return null;
        }

        $signStart = Encode::ALGO_PREFIX_LEN + Encode::SALT_NAME_LEN;
        $hash = substr($rawData, $signStart, Encode::ALGO_LEN[$algo]) ?: '';
        if (empty($hash)) {
            return null;
        }

        return new SignModel($algo, $saltName, $hash);
    }

    public static function decodeSignWithData(string $rawData): ?SignWithData
    {
        $sign = self::decodeSign($rawData);
        if ($sign === null) {
            return null;
        }

        $algo = $sign->getAlgo();
        $dataStart = Encode::ALGO_PREFIX_LEN + Encode::SALT_NAME_LEN + Encode::ALGO_LEN[$algo];
        $data = substr($rawData, $dataStart) ?: '';
        if (empty($data)) {
            return null;
        }

        return new SignWithData($algo, $sign->getSaltName(), $sign->getHash(), $data);
    }
}
