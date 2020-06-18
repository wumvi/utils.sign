<?php

use PHPUnit\Framework\TestCase;
use Wumvi\Utils\Sign;

class SignTest extends TestCase
{
    private const SALT = '123';
    private const SIGN = 's6ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae';
    private const DATA = 'test';


    public function testMakeSign(): void
    {
        $this->assertEquals(
            Sign::getSign(self::DATA, self::SALT, Sign::SHA256),
            self::SIGN,
            'make sha256 sign'
        );

        $this->assertEquals(
            Sign::getSign(self::DATA, self::SALT, Sign::MD5),
            'm5cc03e747a6afbbcbf8be7668acfebee5',
            'make md5 sign'
        );
    }

    public function testMakeSignData(): void
    {
        $signData = self::SIGN . self::DATA;
        $result = Sign::getSignWithData(self::DATA, self::SALT, Sign::SHA256);
        $this->assertEquals($signData, $result, 'make sign data');
    }

    public function testGetSignData(): void
    {
        $signData = self::SIGN . self::DATA;
        $this->assertEquals(
            self::DATA,
            Sign::decodeSignData($signData, self::SALT),
            'make right data'
        );
        $this->assertEquals(
            '',
            Sign::decodeSignData('s7no', self::SALT),
            'wrong algo'
        );

        $this->assertEquals(
            '',
            Sign::decodeSignData('s6d', self::SALT),
            'wrong sign'
        );
    }
}