<?php
declare(strict_types=1);

namespace Wumvi\Utils;

class SignData
{
    private string $algo;
    private string $key;
    private string $data;
    private string $saltName;

    public function __construct(string $algo, string $key, string $data, string $saltName)
    {
        $this->algo = $algo;
        $this->key = $key;
        $this->data = $data;
        $this->saltName = $saltName;
    }

    public function getAlgo(): string
    {
        return $this->algo;
    }

    public function getSaltName(): string
    {
        return $this->saltName;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getData(): string
    {
        return $this->data;
    }
}
