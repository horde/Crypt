<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Test\Pgp\Keyserver\Parser;

use Horde\Crypt\Pgp\Keyserver\Parser\MachineReadable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(MachineReadable::class)]
class MachineReadableTest extends TestCase
{
    private MachineReadable $parser;

    protected function setUp(): void
    {
        $this->parser = new MachineReadable();
    }

    public function testParseEmptyString(): void
    {
        $result = $this->parser->parse('');
        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    public function testParseMachineReadableFormat(): void
    {
        $body = file_get_contents(__DIR__ . '/fixtures/sks-index-mr.txt');
        $result = $this->parser->parse($body);

        $this->assertIsArray($result);
        $this->assertNotEmpty($result);

        // Check first key structure
        $this->assertArrayHasKey('keyid', $result[0]);
        $this->assertArrayHasKey('uids', $result[0]);
        $this->assertArrayHasKey('created', $result[0]);

        // Verify UID parsing
        $this->assertNotEmpty($result[0]['uids']);
        $this->assertArrayHasKey('email', $result[0]['uids'][0]);
    }

    public function testParseSkipsExpiredKeys(): void
    {
        $body = file_get_contents(__DIR__ . '/fixtures/sks-index-mr.txt');
        $result = $this->parser->parse($body);

        // Verify we have results
        $this->assertNotEmpty($result, 'Should have at least some non-expired keys');

        // Expired keys should not be in results
        foreach ($result as $key) {
            if (!empty($key['expires'])) {
                $this->assertGreaterThan(time(), $key['expires'], 'Expired keys should be filtered out');
            }
        }

        // The fixture has an expired key at line 4 (expires: 1609459200 which is in the past)
        // Count should be less than total pub: lines due to filtering
        $this->assertLessThan(5, count($result), 'Should filter out expired keys');
    }

    public function testParseExtractsEmailsFromUIDs(): void
    {
        $body = "pub:ABCD:1:4096:1640000000::\nuid:Test User <test@example.com>:::\n";
        $result = $this->parser->parse($body);

        $this->assertCount(1, $result);
        $this->assertEquals('test@example.com', $result[0]['uids'][0]['email']);
    }
}
