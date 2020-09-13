<?php
declare(strict_types=1);

namespace Wumvi\Utils;

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

    public static function getRawSign(string $data, string $salt, string $algo = self::DEFAULT_ALGO): string
    {
        return hash(self::ALGO_NAME[$algo], $data . $salt, false);
    }

    public static function getSign(
        string $data,
        string $salt,
        string $saltName,
        string $algo = self::DEFAULT_ALGO
    ): string {
        $saltName = substr($saltName, 0, self::SALT_NAME_LEN);
        return $algo . $saltName . self::getRawSign($data, $salt, $algo);
    }

    public static function getSignWithData(
        string $data,
        string $salt,
        string $saltName,
        string $algo = self::DEFAULT_ALGO
    ): string {
        return self::getSign($data, $salt, $saltName, $algo) . $data;
    }

    public static function decodeSignData(string $rawData): ?SignData
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
        $sign = substr($rawData, $signStart, self::ALGO_LEN[$algo]) ?: '';
        if (empty($sign)) {
            return null;
        }

        $dataStart = self::ALGO_PREFIX_LEN + self::SALT_NAME_LEN + self::ALGO_LEN[$algo];
        $data = substr($rawData, $dataStart) ?: '';
        if (empty($data)) {
            return null;
        }

        return new SignData($algo, $sign, $data, $saltName);
    }

    public static function checkSignData(SignData $data, string $salt): bool
    {
        return self::getRawSign($data->getData(), $salt, $data->getAlgo()) === $data->getKey();
    }
}
