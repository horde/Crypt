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

use Horde\Crypt\Pgp\Keyserver\Parser\KeyExtractor;
use Horde\Crypt\Pgp\Keyserver\Parser\MachineReadable;
use Horde\Crypt\Pgp\Keyserver\Protocol\HkpV1;
use Horde\Crypt\Pgp\Keyserver\Protocol\HkpV2;
use Horde_Crypt_Pgp;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * Automatic protocol detection for keyservers.
 *
 * Probes the server for HKP v2 support and falls back to HKP v1/SKS if unavailable.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
final class ProtocolDetector
{
    public function __construct(
        private readonly string $serverUrl,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly Horde_Crypt_Pgp $pgp,
    ) {}

    public function detect(): ProtocolInterface
    {
        // Try HKP v2 first (modern)
        try {
            $request = $this->requestFactory->createRequest(
                'GET',
                $this->serverUrl . '/pks/v2/'
            );
            $response = $this->httpClient->sendRequest($request);

            if ($response->getStatusCode() === 200) {
                return new HkpV2(
                    $this->serverUrl,
                    $this->httpClient,
                    $this->requestFactory,
                    $this->streamFactory,
                    $this->pgp
                );
            }
        } catch (Throwable) {
            // v2 not available, fall back to v1
        }

        // Fall back to HKP v1 (SKS)
        return new HkpV1(
            $this->serverUrl,
            $this->httpClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp,
            new KeyExtractor(),
            new MachineReadable()
        );
    }
}
