<?php

use PHPUnit\Framework\TestCase;
use Wumvi\Utils\Sign;

class SignTest extends TestCase
{
    private const SALT_NAME = 'sn';
    private const SALT_VALUE = '123';
    private const SHA256_OF_DATA = 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae';
    private const MD5_OF_DATA = 'cc03e747a6afbbcbf8be7668acfebee5';
    private const DATA = 'test';

    public function testCreateSign(): void
    {
        self::assertEquals(
            Sign::createSign(self::DATA, self::SALT_NAME, self::SALT_VALUE, Sign::SHA256),
            Sign::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA,
            'make sha256 sign'
        );

        self::assertEquals(
            Sign::createSign(self::DATA, self::SALT_NAME, self::SALT_VALUE, Sign::MD5),
            Sign::MD5 . self::SALT_NAME . self::MD5_OF_DATA,
            'make md5 sign'
        );

        $signData = Sign::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA . self::DATA;
        $result = Sign::createSignWithData(self::DATA, self::SALT_NAME, self::SALT_VALUE, Sign::SHA256);
        self::assertEquals($signData, $result, 'make sign with data');
    }

    public function testDecodeSign(): void
    {
        $signRaw = Sign::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA;
        $sign = Sign::decodeSign($signRaw);
        self::assertEquals($sign->getAlgo(), Sign::SHA256, 'check right algo');
        self::assertEquals($sign->getHash(), self::SHA256_OF_DATA, 'check right hash');
        self::assertEquals($sign->getSaltName(), self::SALT_NAME, 'check right salt name');

        $sign = Sign::decodeSign('123');
        self::assertEquals($sign, null, 'check wrong algo');
        $sign = Sign::decodeSign(Sign::SHA256);
        self::assertEquals($sign, null, 'check empty salt name');
        $sign = Sign::decodeSign(Sign::SHA256 . self::SALT_NAME);
        self::assertEquals($sign, null, 'check empty hash');

        $signRaw = Sign::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA . self::DATA;
        $sign = Sign::decodeSignWithData($signRaw);
        self::assertEquals($sign->getData(), self::DATA, 'check right data');
        $signRaw = Sign::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA . '';
        $sign = Sign::decodeSignWithData($signRaw);
        self::assertEquals($sign, null, 'check empty data');
        $sign = Sign::decodeSignWithData('wrong-data');
        self::assertEquals($sign, null, 'check wrong data');
    }

    public function testInvalidAlgoName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Sign::createRawSign('data', '123', '334');
    }

    public function testCheckSign(): void
    {
        $result = Sign::checkRawSign(self::DATA, Sign::SHA256, self::SALT_VALUE, self::SHA256_OF_DATA);
        self::assertTrue($result, 'check correct hash');

        $result = Sign::checkRawSign(self::DATA, Sign::SHA256, self::SALT_VALUE, 'wrong-hash');
        self::assertFalse($result, 'check wrong hash');

        $data = Sign::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA;
        $result = Sign::checkSign($data, self::DATA, self::SALT_VALUE);
        self::assertTrue($result, 'check right hash');

        $data = 'wrong-data';
        $result = Sign::checkSign($data, self::DATA, self::SALT_VALUE);
        self::assertFalse($result, 'check wrong data');
    }
}