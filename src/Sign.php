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
    public const SHA256 = 's6';
    public const SHA1 = 's1';
    public const MD5 = 'm5';

    private const ALGO_LEN = [
        self::MD5 => 32,
        self::SHA1 => 40,
        self::SHA256 => 64,
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

    public static function getSign(string $data, string $salt, string $algo = self::DEFAULT_ALGO): string
    {
        return $algo . self::getRawSign($data, $salt, $algo);
    }

    public static function getSignWithData(string $data, string $salt, string $algo = self::DEFAULT_ALGO): string
    {
        return self::getSign($data, $salt, $algo) . $data;
    }

    public static function decodeSignData(string $rawData, string $salt): string
    {
        $algo = substr($rawData, 0, 2) ?: '';
        if (!array_key_exists($algo, self::ALGO_NAME)) {
            return '';
        }
        $sign = substr($rawData, 2, self::ALGO_LEN[$algo]) ?: '';
        $data = substr($rawData, self::ALGO_LEN[$algo] + 2) ?: '';

        return self::getRawSign($data, $salt, $algo) === $sign ? $data : '';
    }
}
