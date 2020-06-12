<?php

use PHPUnit\Framework\TestCase;
use Wumvi\Utils\Sign;

class SignTest extends TestCase
{
    private const SALT = '123';
    private const SIGN = 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae';
    private const DATA = 'test';

    public function testGetCryptSalt(): void
    {
        $_ENV['CRYPT_SIGN'] = self::SALT;
        $this->assertTrue(
            Sign::getCryptSalt() === self::SALT,
            'get salt'
        );
    }

    public function testWrongSign()
    {
        $this->expectException(\Exception::class);
        Sign::getCryptSalt('no-key');
    }

    public function testMakeSign(): void
    {
        $result = Sign::makeSign(self::DATA, self::SALT) === self::SIGN;
        $this->assertTrue($result, 'make sign');
    }

    public function testMakeSignData(): void
    {
        $signData = self::SIGN . self::DATA;
        $result = Sign::makeSignData(self::DATA, self::SALT);
        $this->assertTrue(
            $result === $signData,
            'make sign data'
        );
    }

    public function testGetSignData(): void
    {
        $signData = self::SIGN . self::DATA;
        $this->assertTrue(
            Sign::getSignData($signData, self::SALT) === self::DATA,
            'make right data'
        );
        $this->assertTrue(
            Sign::getSignData('no', self::SALT) === '',
            'make wrong data'
        );
    }
}