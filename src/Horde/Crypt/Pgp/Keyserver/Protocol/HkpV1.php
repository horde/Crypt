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

use Horde\Crypt\Pgp\Keyserver\Exception\KeyAlreadyExistsException;
use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;
use Horde\Crypt\Pgp\Keyserver\Exception\ServerErrorException;
use Horde\Crypt\Pgp\Keyserver\Parser\KeyExtractor;
use Horde\Crypt\Pgp\Keyserver\Parser\MachineReadable;
use Horde\Crypt\Pgp\Keyserver\ProtocolInterface;
use Horde_Crypt_Pgp;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Throwable;

/**
 * HKP v1 protocol implementation (SKS keyserver).
 *
 * Implements the legacy HKP protocol with SKS-specific quirks:
 * - Empty User-Agent to avoid HTML responses
 * - URL-encoded response handling
 * - Retry logic for broken servers
 * - Machine-readable format parsing
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
final class HkpV1 implements ProtocolInterface
{
    private const MAX_RETRIES = 3;

    public function __construct(
        private readonly string $serverUrl,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly Horde_Crypt_Pgp $pgp,
        private readonly KeyExtractor $keyExtractor,
        private readonly MachineReadable $mrParser,
    ) {}

    public function getKey(string $keyId): string
    {
        $uri = $this->serverUrl . '/pks/lookup?' . http_build_query([
            'op' => 'get',
            'search' => $this->pgp->getKeyIDString($keyId),
        ]);

        $request = $this->requestFactory->createRequest('GET', $uri)
            ->withHeader('User-Agent', ''); // Empty UA to avoid HTML responses

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new ServerErrorException('HTTP request failed: ' . $e->getMessage(), 0, $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new KeyNotFoundException("Key not found: $keyId");
        }

        $body = (string) $response->getBody();

        // Handle URL-encoded responses (SKS quirk)
        if (urlencode(urldecode($body)) === $body) {
            $body = urldecode($body);
        }

        return $this->keyExtractor->extract($body);
    }

    public function putKey(string $armoredKey): void
    {
        // Check if key already exists
        $info = $this->pgp->pgpPacketInformation($armoredKey);
        try {
            $this->getKey($info['keyid']);
            throw new KeyAlreadyExistsException("Key already exists on server");
        } catch (KeyNotFoundException) {
            // Good, proceed with upload
        }

        $uri = $this->serverUrl . '/pks/add';
        $body = 'keytext=' . urlencode(rtrim($armoredKey));

        $request = $this->requestFactory->createRequest('POST', $uri)
            ->withHeader('User-Agent', 'Horde Application Framework')
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Connection', 'close')
            ->withBody($this->streamFactory->createStream($body));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new ServerErrorException('HTTP request failed: ' . $e->getMessage(), 0, $e);
        }

        if ($response->getStatusCode() >= 400) {
            throw new ServerErrorException("Failed to upload key: HTTP " . $response->getStatusCode());
        }
    }

    public function findKeyByEmail(string $email): string
    {
        $uri = $this->serverUrl . '/pks/lookup?' . http_build_query([
            'op' => 'index',
            'options' => 'mr',
            'search' => $email,
        ]);

        // SKS quirk: retry up to 3 times for broken servers
        $body = null;
        for ($i = 0; $i < self::MAX_RETRIES; $i++) {
            $request = $this->requestFactory->createRequest('GET', $uri)
                ->withHeader('User-Agent', '');

            try {
                $response = $this->httpClient->sendRequest($request);
            } catch (Throwable $e) {
                if ($i === self::MAX_RETRIES - 1) {
                    throw new ServerErrorException('HTTP request failed: ' . $e->getMessage(), 0, $e);
                }
                continue; // Retry
            }

            // Check Content-Type (some broken servers return HTML)
            $contentType = $response->getHeaderLine('Content-Type');
            if (!str_starts_with($contentType, 'text/plain')) {
                continue; // Retry
            }

            $body = (string) $response->getBody();

            // Handle URL-encoded responses
            if (urlencode(urldecode($body)) === $body) {
                $body = urldecode($body);
            }

            break;
        }

        if (!$body) {
            throw new KeyNotFoundException("No keys found for: $email");
        }

        // Check if response contains a full key block
        if (strpos($body, '-----BEGIN PGP PUBLIC KEY BLOCK') !== false) {
            return $this->keyExtractor->extract($body);
        }

        // Parse machine-readable format and find matching key
        $keys = $this->mrParser->parse($body);
        $matchingKey = $this->findMatchingKey($keys, $email);

        if (!$matchingKey) {
            throw new KeyNotFoundException("No matching key for: $email");
        }

        // Retrieve full key
        return $this->getKey($matchingKey['keyid']);
    }

    public function isSupported(): bool
    {
        // HKP v1 is always available as fallback
        return true;
    }

    private function findMatchingKey(array $keys, string $email): ?array
    {
        foreach ($keys as $key) {
            // Skip expired keys
            if (!empty($key['expires']) && $key['expires'] <= time()) {
                continue;
            }

            // Match email in UIDs
            foreach ($key['uids'] as $uid) {
                if ($uid['email'] === $email) {
                    return $key;
                }
            }
        }
        return null;
    }
}
