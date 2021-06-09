<?php
declare(strict_types=1);

namespace Wumvi\Sign;

class Check
{
    public static function checkSign(string $signFormRequest, string $data, string $saltValue): bool
    {
        $sign = Decode::decodeSign($signFormRequest);
        if ($sign === null) {
            return false;
        }

        return Encode::createRawSign($data, $saltValue, $sign->getAlgo()) === $sign->getHash();
    }

    public static function checkRawSign(string $data, string $algo, string $saltValue, string $hash): bool
    {
        return Encode::createRawSign($data, $saltValue, $algo) === $hash;
    }
}
