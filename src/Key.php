<?php

namespace ricwein\Crypto;

use ricwein\Crypto\Exceptions\CannotAccessHiddenException;

abstract class Key
{
    /**
     * @throws CannotAccessHiddenException
     */
    public function __clone(): void
    {
        throw new CannotAccessHiddenException();
    }

    /**
     * @throws CannotAccessHiddenException
     */
    public function __sleep(): array
    {
        throw new CannotAccessHiddenException();
    }

    /**
     * @throws CannotAccessHiddenException
     */
    public function __wakeup()
    {
        throw new CannotAccessHiddenException();
    }

    public function __toString(): string
    {
        return '';
    }

    abstract public function __debugInfo(): array;
}
