<?php
declare(strict_types=1);

namespace Wumvi\Sign\Model;

class Sign
{
    public function __construct(
        protected string $algo,
        protected string $saltName,
        protected string $hash
    ) {
    }

    public function getAlgo(): string
    {
        return $this->algo;
    }

    public function getSaltName(): string
    {
        return $this->saltName;
    }

    public function getHash(): string
    {
        return $this->hash;
    }
}
