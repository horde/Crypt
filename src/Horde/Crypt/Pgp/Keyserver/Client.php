<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Michael Slusarz <slusarz@horde.org>
 * @author   Ralf Lang <lang@b1-systems.de>
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt
 */

namespace Horde\Crypt\Pgp\Keyserver;

use Horde_Crypt_Pgp;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * PSR-compliant keyserver client.
 *
 * Modern keyserver client using PSR-7/17/18 standards with automatic protocol detection.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
final class Client
{
    private readonly ProtocolInterface $protocol;

    public function __construct(
        private readonly string $serverUrl,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly Horde_Crypt_Pgp $pgp,
        ?ProtocolInterface $protocol = null,
    ) {
        $this->protocol = $protocol ?? $this->detectProtocol();
    }

    private function detectProtocol(): ProtocolInterface
    {
        $detector = new ProtocolDetector(
            $this->serverUrl,
            $this->httpClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp
        );
        return $detector->detect();
    }

    public function getKey(string $keyId): string
    {
        return $this->protocol->getKey($keyId);
    }

    public function putKey(string $armoredKey): void
    {
        $this->protocol->putKey($armoredKey);
    }

    public function findKeyByEmail(string $email): string
    {
        return $this->protocol->findKeyByEmail($email);
    }
}
