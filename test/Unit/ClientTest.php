<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Test\Pgp\Keyserver;

use Horde\Crypt\Pgp\Keyserver\Client;
use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;
use Horde\Crypt\Pgp\Keyserver\Protocol\HkpV1;
use Horde\Http\Client\Mock;
use Horde\Http\Client\Options;
use Horde\Http\RequestFactory;
use Horde\Http\StreamFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Horde_Crypt_Pgp;

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
        $this->pgp = $this->createMock(Horde_Crypt_Pgp::class);
    }

    public function testGetKeyDelegatesToProtocol(): void
    {
        $keyContent = file_get_contents(__DIR__ . '/fixtures/sks-get-response.txt');

        $this->mockClient->addResponse(
            $this->streamFactory->createStream('Not Found'),
            404,
            'http://example.com/pks/v2/',
            []
        );

        $this->mockClient->addResponse(
            $this->streamFactory->createStream($keyContent),
            200,
            'http://example.com/pks/lookup?op=get&search=0xABCD',
            ['Content-Type' => 'text/html']
        );

        $this->pgp->method('getKeyIDString')->willReturn('0xABCD');

        $client = new Client(
            'http://example.com',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp
        );

        $result = $client->getKey('ABCD');
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
            'http://example.com/pks/lookup?op=get&search=0xNOTFOUND',
            []
        );

        $this->pgp->method('getKeyIDString')->willReturn('0xNOTFOUND');

        $client = new Client(
            'http://example.com',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $this->pgp
        );

        $this->expectException(KeyNotFoundException::class);
        $client->getKey('NOTFOUND');
    }

    public function testCanInjectProtocol(): void
    {
        // Use anonymous class instead of mocking final class
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
