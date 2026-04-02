<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Test\Pgp\Keyserver\Integration;

use Horde\Crypt\Pgp\Keyserver\Client;
use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;
use Horde\Http\Client\Mock;
use Horde\Http\Client\Options;
use Horde\Http\RequestFactory;
use Horde\Http\StreamFactory;
use Horde_Crypt_Pgp;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Client::class)]
class ClientTest extends TestCase
{
    private Mock $mockClient;
    private RequestFactory $requestFactory;
    private StreamFactory $streamFactory;
    private Horde_Crypt_Pgp $pgp;

    protected function setUp(): void
    {
        $this->mockClient = new Mock(null, null, new Options());
        $this->requestFactory = new RequestFactory();
        $this->streamFactory = new StreamFactory();
        // REAL Horde_Crypt_Pgp instance (not mocked)
        $this->pgp = new Horde_Crypt_Pgp();
    }

    public function testGetKeyDelegatesToProtocol(): void
    {
        $keyContent = file_get_contents(__DIR__ . '/../Unit/fixtures/sks-get-response.txt');

        $this->mockClient->addResponse(
            $this->streamFactory->createStream('Not Found'),
            404,
            'http://example.com/pks/v2/',
            []
        );

        $this->mockClient->addResponse(
            $this->streamFactory->createStream($keyContent),
            200,
            'http://example.com/pks/lookup?op=get&search=0xE93D47A8BA9C8DD1',
            ['Content-Type' => 'text/html']
        );

        $client = new Client(
            'http://example.com',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp
        );

        $result = $client->getKey('E93D47A8BA9C8DD1');
        $this->assertStringContainsString('-----BEGIN PGP PUBLIC KEY BLOCK-----', $result);
    }

    public function testGetKeyThrowsNotFoundException(): void
    {
        $this->mockClient->addResponse(
            $this->streamFactory->createStream('Not Found'),
            404,
            'http://example.com/pks/v2/',
            []
        );

        $this->mockClient->addResponse(
            $this->streamFactory->createStream('Not Found'),
            404,
            'http://example.com/pks/lookup?op=get&search=0xDEADBEEF',
            []
        );

        $client = new Client(
            'http://example.com',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp
        );

        $this->expectException(KeyNotFoundException::class);
        $client->getKey('DEADBEEF');
    }

    public function testCanInjectProtocol(): void
    {
        // Use anonymous class for protocol
        $protocol = new class implements \Horde\Crypt\Pgp\Keyserver\ProtocolInterface {
            public function getKey(string $keyId): string
            {
                return 'test-key-data';
            }

            public function putKey(string $armoredKey): void {}

            public function findKeyByEmail(string $email): string
            {
                return '';
            }

            public function isSupported(): bool
            {
                return true;
            }
        };

        $client = new Client(
            'http://example.com',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp,
            $protocol
        );

        $result = $client->getKey('TESTKEY');
        $this->assertEquals('test-key-data', $result);
    }
}
