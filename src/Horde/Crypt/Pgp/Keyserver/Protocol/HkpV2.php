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

namespace Horde\Crypt\Pgp\Keyserver\Protocol;

use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;
use Horde\Crypt\Pgp\Keyserver\Exception\ServerErrorException;
use Horde\Crypt\Pgp\Keyserver\ProtocolInterface;
use Horde_Crypt_Pgp;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * HKP v2 protocol implementation (modern keyservers like Hockeypuck, Hagrid).
 *
 * Implements the modern HKP v2 protocol with:
 * - RESTful endpoints
 * - Proper Content-Type headers
 * - HTTP status codes (404, 410, 422)
 * - JSON index responses
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
final class HkpV2 implements ProtocolInterface
{
    public function __construct(
        private readonly string $serverUrl,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly Horde_Crypt_Pgp $pgp,
    ) {}

    public function getKey(string $keyId): string
    {
        // Use v2 endpoint with proper RESTful structure
        $uri = $this->serverUrl . '/pks/v2/certs/by-keyid/' . $keyId;

        $request = $this->requestFactory->createRequest('GET', $uri)
            ->withHeader('Accept', 'application/pgp-keys');

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new ServerErrorException('HTTP request failed: ' . $e->getMessage(), 0, $e);
        }

        return match ($response->getStatusCode()) {
            200 => (string) $response->getBody(),
            404 => throw new KeyNotFoundException("Key not found: $keyId"),
            410 => throw new KeyNotFoundException("Key deleted (RTBF): $keyId"),
            default => throw new ServerErrorException("Server error: HTTP " . $response->getStatusCode()),
        };
    }

    public function putKey(string $armoredKey): void
    {
        // HKP v2 supports both POST and PUT
        $uri = $this->serverUrl . '/pks/v2/submit';

        $request = $this->requestFactory->createRequest('POST', $uri)
            ->withHeader('Content-Type', 'application/pgp-keys')
            ->withBody($this->streamFactory->createStream($armoredKey));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new ServerErrorException('HTTP request failed: ' . $e->getMessage(), 0, $e);
        }

        match ($response->getStatusCode()) {
            200, 202 => null, // Success or accepted with modifications
            422 => throw new ServerErrorException("Malformed key submission"),
            403 => throw new ServerErrorException("Operation prohibited by policy"),
            default => throw new ServerErrorException("Failed to upload key: HTTP " . $response->getStatusCode()),
        };
    }

    public function findKeyByEmail(string $email): string
    {
        // Use v2 JSON index endpoint
        $uri = $this->serverUrl . '/pks/v2/index?' . http_build_query([
            'search' => $email,
        ]);

        $request = $this->requestFactory->createRequest('GET', $uri)
            ->withHeader('Accept', 'application/json');

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new ServerErrorException('HTTP request failed: ' . $e->getMessage(), 0, $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new KeyNotFoundException("No keys found for: $email");
        }

        $data = json_decode((string) $response->getBody(), true);

        if (empty($data['keys'])) {
            throw new KeyNotFoundException("No keys found for: $email");
        }

        // Return most recent non-expired key
        $key = $this->selectBestKey($data['keys'], $email);
        return $this->getKey($key['keyid']);
    }

    public function isSupported(): bool
    {
        try {
            $request = $this->requestFactory->createRequest(
                'GET',
                $this->serverUrl . '/pks/v2/'
            );
            $response = $this->httpClient->sendRequest($request);
            return $response->getStatusCode() === 200;
        } catch (Throwable) {
            return false;
        }
    }

    private function selectBestKey(array $keys, string $email): array
    {
        $valid = array_filter(
            $keys,
            fn($k)
            => empty($k['expires']) || $k['expires'] > time()
        );

        if (empty($valid)) {
            throw new KeyNotFoundException("No valid keys for: $email");
        }

        // Sort by creation date descending
        usort($valid, fn($a, $b) => $b['created'] <=> $a['created']);

        return $valid[0];
    }
}
