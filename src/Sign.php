<?php
declare(strict_types=1);

namespace Wumvi\Utils;

use Wumvi\Utils\Model\SignWithData;
use \Wumvi\Utils\Model\Sign as SignModel;

/**
 * Получение переменных и работы с массивами GET или POST
 *
 * @author Козленко В.Л.
 */
class Sign
{
    private const ALGO_PREFIX_LEN = 2;
    private const SALT_NAME_LEN = 2;
    public const SHA256 = 's6';
    public const SHA1 = 's1';
    public const MD5 = 'm5';
    public const DIRECT = 'dr';

    private const ALGO_LEN = [
        self::MD5 => 32,
        self::SHA1 => 40,
        self::SHA256 => 64,
        self::DIRECT => 15,
    ];

    private const ALGO_NAME = [
        self::MD5 => 'md5',
        self::SHA1 => 'sha1',
        self::SHA256 => 'sha256',
    ];

    private const DEFAULT_ALGO = self::MD5;

    public static function createRawSign(string $data, string $saltValue, string $algo = self::DEFAULT_ALGO): string
    {
        if (!array_key_exists($algo, self::ALGO_NAME)) {
            throw new \InvalidArgumentException('wrong algo name');
        }

        return hash(self::ALGO_NAME[$algo], $data . $saltValue, false);
    }

    public static function createSign(
        string $data,
        string $saltName,
        string $saltValue,
        string $algo = self::DEFAULT_ALGO
    ): string {
        $saltName2Name = substr($saltName, 0, self::SALT_NAME_LEN);

        return $algo . $saltName2Name . self::createRawSign($data, $saltValue, $algo);
    }

    public static function createSignWithData(
        string $data,
        string $saltName,
        string $saltValue,
        string $algo = self::DEFAULT_ALGO
    ): string {
        return self::createSign($data, $saltName, $saltValue, $algo) . $data;
    }

    public static function decodeSign(string $rawData): ?SignModel
    {
        $algo = substr($rawData, 0, self::ALGO_PREFIX_LEN) ?: '';
        if (!array_key_exists($algo, self::ALGO_NAME)) {
            return null;
        }

        $saltName = substr($rawData, self::ALGO_PREFIX_LEN, self::SALT_NAME_LEN);
        if (empty($saltName)) {
            return null;
        }

        $signStart = self::ALGO_PREFIX_LEN + self::SALT_NAME_LEN;
        $hash = substr($rawData, $signStart, self::ALGO_LEN[$algo]) ?: '';
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
        $dataStart = self::ALGO_PREFIX_LEN + self::SALT_NAME_LEN + self::ALGO_LEN[$algo];
        $data = substr($rawData, $dataStart) ?: '';
        if (empty($data)) {
            return null;
        }

        return new SignWithData($algo, $sign->getSaltName(), $sign->getHash(), $data);
    }


    public static function checkSign(string $signFormRequest, string $data, string $saltValue): bool
    {
        $sign = self::decodeSign($signFormRequest);
        if ($sign === null) {
            return false;
        }

        return self::createRawSign($data, $saltValue, $sign->getAlgo()) === $sign->getHash();
    }

    public static function checkRawSign(string $data, string $algo, string $saltValue, string $hash): bool
    {
        return self::createRawSign($data, $saltValue, $algo) === $hash;
    }
}
