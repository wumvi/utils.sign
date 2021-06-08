<?php
declare(strict_types=1);

namespace Wumvi\Utils\Sign\Model;

class SignWithData extends Sign
{
    public function __construct(
        string $algo,
        string $saltName,
        string $hash,
        protected string $data,
    ) {
        parent::__construct($algo, $saltName, $hash);
    }

    public function getData(): string
    {
        return $this->data;
    }
}
