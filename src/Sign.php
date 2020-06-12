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
    public static function getCryptSalt(string $key = 'CRYPT_SIGN'): string
    {
        $salt = $_ENV[$key] ?? '';
        if (empty($salt)) {
            throw new \Exception('salt-is-empty');
        }

        return $salt;
    }

    public static function makeSign(string $data, string $salt): string
    {
        return hash('sha256', $data . $salt, false);
    }

    public static function makeSignData(string $data, string $salt): string
    {
        return self::makeSign($data, $salt) . $data;
    }

    public static function getSignData(string $rawData, string $salt): string
    {
        $sign = substr($rawData, 0, 64) ?: '';
        $data = substr($rawData, 64) ?: '';

        return self::makeSign($data, $salt) === $sign ? $data : '';
    }
}
