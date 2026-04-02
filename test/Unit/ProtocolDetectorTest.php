<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Test\Pgp\Keyserver;

use Horde\Crypt\Pgp\Keyserver\ProtocolDetector;
use Horde\Crypt\Pgp\Keyserver\Protocol\HkpV1;
use Horde\Crypt\Pgp\Keyserver\Protocol\HkpV2;
use Horde\Http\Client\Mock;
use Horde\Http\Client\Options;
use Horde\Http\RequestFactory;
use Horde\Http\ResponseFactory;
use Horde\Http\StreamFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Horde_Crypt_Pgp;

#[CoversClass(ProtocolDetector::class)]
class ProtocolDetectorTest extends TestCase
{
    private Mock $mockClient;
    private RequestFactory $requestFactory;
    private StreamFactory $streamFactory;
    private ResponseFactory $responseFactory;

    protected function setUp(): void
    {
        $this->mockClient = new Mock(null, null, new Options());
        $this->requestFactory = new RequestFactory();
        $this->streamFactory = new StreamFactory();
        $this->responseFactory = new ResponseFactory();
    }

    public function testDetectsHkpV2(): void
    {
        // Mock successful v2 probe
        $this->mockClient->addResponse(
            $this->streamFactory->createStream('OK'),
            200,
            'https://keys.openpgp.org/pks/v2/',
            ['Content-Type' => 'text/html']
        );

        $pgp = $this->createMock(Horde_Crypt_Pgp::class);

        $detector = new ProtocolDetector(
            'https://keys.openpgp.org',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $pgp
        );

        $protocol = $detector->detect();
        $this->assertInstanceOf(HkpV2::class, $protocol);
    }

    public function testFallsBackToHkpV1(): void
    {
        // Mock failed v2 probe
        $this->mockClient->addResponse(
            $this->streamFactory->createStream('Not Found'),
            404,
            'http://pool.sks-keyservers.net:11371/pks/v2/',
            ['Content-Type' => 'text/html']
        );

        $pgp = $this->createMock(Horde_Crypt_Pgp::class);

        $detector = new ProtocolDetector(
            'http://pool.sks-keyservers.net:11371',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $pgp
        );

        $protocol = $detector->detect();
        $this->assertInstanceOf(HkpV1::class, $protocol);
    }

    public function testFallsBackOnException(): void
    {
        // Mock will throw exception for missing response
        $pgp = $this->createMock(Horde_Crypt_Pgp::class);

        $detector = new ProtocolDetector(
            'http://broken.example.com',
            $this->mockClient,
            $this->requestFactory,
            $this->streamFactory,
            $pgp
        );

        // Should fall back to v1 without throwing
        $protocol = $detector->detect();
        $this->assertInstanceOf(HkpV1::class, $protocol);
    }
}
