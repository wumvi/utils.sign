<?php

use PHPUnit\Framework\TestCase;
use Wumvi\Sign\Encode;
use Wumvi\Sign\Decode;
use Wumvi\Sign\Check;
use Wumvi\Sign\SaltStorage;

class SignTest extends TestCase
{
    private const SALT_NAME = 'sn';
    private const SALT_VALUE = '123';
    private const SHA256_OF_DATA = 'ecd71870d1963316a97e3ac3408c9835ad8cf0f3c1bc703527c30265534f75ae';
    private const MD5_OF_DATA = 'cc03e747a6afbbcbf8be7668acfebee5';
    private const DATA = 'test';
    private SaltStorage $saltStorage;

    protected function setUp(): void
    {
        $this->saltStorage = new SaltStorage([
            'sn' => '123'
        ]);
    }

    public function testCreateSign(): void
    {
        self::assertEquals(
            Encode::createSign(self::DATA, self::SALT_NAME, self::SALT_VALUE, Encode::SHA256),
            Encode::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA,
            'make sha256 sign'
        );

        self::assertEquals(
            Encode::createSign(self::DATA, self::SALT_NAME, self::SALT_VALUE, Encode::MD5),
            Encode::MD5 . self::SALT_NAME . self::MD5_OF_DATA,
            'make md5 sign'
        );

        $signData = Encode::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA . self::DATA;
        $result = Encode::createSignWithData(self::DATA, self::SALT_NAME, self::SALT_VALUE, Encode::SHA256);
        self::assertEquals($signData, $result, 'make sign with data');
    }

    public function testDecodeSign(): void
    {
        $signRaw = Encode::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA;
        $sign = Decode::decodeSign($signRaw);
        self::assertEquals($sign->getAlgo(), Encode::SHA256, 'check right algo');
        self::assertEquals($sign->getHash(), self::SHA256_OF_DATA, 'check right hash');
        self::assertEquals($sign->getSaltName(), self::SALT_NAME, 'check right salt name');

        $sign = Decode::decodeSign('123');
        self::assertEquals($sign, null, 'check wrong algo');
        $sign = Decode::decodeSign(Encode::SHA256);
        self::assertEquals($sign, null, 'check empty salt name');
        $sign = Decode::decodeSign(Encode::SHA256 . self::SALT_NAME);
        self::assertEquals($sign, null, 'check empty hash');

        $signRaw = Encode::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA . self::DATA;
        $sign = Decode::decodeSignWithData($signRaw);
        self::assertEquals($sign->getData(), self::DATA, 'check right data');
        $signRaw = Encode::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA . '';
        $sign = Decode::decodeSignWithData($signRaw);
        self::assertEquals($sign, null, 'check empty data');
        $sign = Decode::decodeSignWithData('wrong-data');
        self::assertEquals($sign, null, 'check wrong data');
    }

    public function testInvalidAlgoName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Encode::createRawSign('data', '123', '334');
    }

    public function testCheckSign(): void
    {
        $result = Check::checkRawSign(self::DATA, Encode::SHA256, self::SALT_VALUE, self::SHA256_OF_DATA);
        self::assertTrue($result, 'check correct hash');

        $result = Check::checkRawSign(self::DATA, Encode::SHA256, self::SALT_VALUE, 'wrong-hash');
        self::assertFalse($result, 'check wrong hash');

        $data = Encode::SHA256 . self::SALT_NAME . self::SHA256_OF_DATA;
        $result = Check::checkSign($data, self::DATA, $this->saltStorage);
        self::assertTrue($result, 'check right hash');

        $data = 'wrong-data';
        $result = Check::checkSign($data, self::DATA, $this->saltStorage);
        self::assertFalse($result, 'check wrong data');
    }
}