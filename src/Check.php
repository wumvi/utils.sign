<?php
declare(strict_types=1);

namespace Wumvi\Sign;

class Check
{
    public static function checkSign(string $signRaw, string $data, SaltStorage $saltStorage): bool
    {
        $sign = Decode::decodeSign($signRaw);
        if ($sign === null) {
            return false;
        }

        $saltValue = $saltStorage->getSaltByName($sign->getSaltName());

        return Encode::createRawSign($data, $saltValue, $sign->getAlgo()) === $sign->getHash();
    }

    public static function checkRawSign(string $data, string $algo, string $saltValue, string $hash): bool
    {
        return Encode::createRawSign($data, $saltValue, $algo) === $hash;
    }
}
