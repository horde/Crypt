<?php

declare(strict_types=1);

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Test\Pgp\Keyserver\Parser;

use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;
use Horde\Crypt\Pgp\Keyserver\Parser\KeyExtractor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyExtractor::class)]
class KeyExtractorTest extends TestCase
{
    private KeyExtractor $extractor;

    protected function setUp(): void
    {
        $this->extractor = new KeyExtractor();
    }

    public function testExtractKeyFromPlainText(): void
    {
        $body = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";
        $result = $this->extractor->extract($body);

        $this->assertStringContainsString('-----BEGIN PGP PUBLIC KEY BLOCK-----', $result);
        $this->assertStringContainsString('-----END PGP PUBLIC KEY BLOCK-----', $result);
    }

    public function testExtractKeyFromHTML(): void
    {
        $html = file_get_contents(__DIR__ . '/fixtures/sks-get-response.txt');
        $result = $this->extractor->extract($html);

        $this->assertStringStartsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----', $result);
        $this->assertStringContainsString('-----END PGP PUBLIC KEY BLOCK-----', $result);
    }

    public function testExtractKeyThrowsWhenNoKey(): void
    {
        $this->expectException(KeyNotFoundException::class);
        $this->extractor->extract('No key here');
    }

    public function testExtractKeyThrowsWhenIncomplete(): void
    {
        $this->expectException(KeyNotFoundException::class);
        $this->extractor->extract('-----BEGIN PGP PUBLIC KEY BLOCK----- but no end');
    }
}
