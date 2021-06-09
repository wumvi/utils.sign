<?php
declare(strict_types=1);

namespace Wumvi\Sign;

/**
 * Получение переменных и работы с массивами GET или POST
 *
 * @author Козленко В.Л.
 */
class Encode
{
    public const ALGO_PREFIX_LEN = 2;
    public const SALT_NAME_LEN = 2;
    public const SHA256 = 's6';
    public const SHA1 = 's1';
    public const MD5 = 'm5';
    public const DIRECT = 'dr';

    public const ALGO_LEN = [
        self::MD5 => 32,
        self::SHA1 => 40,
        self::SHA256 => 64,
        self::DIRECT => 15,
    ];

    public const ALGO_NAME = [
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
}
