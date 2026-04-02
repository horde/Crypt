<?php

declare(strict_types=1);

/**
 * Copyright 2013-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Pgp\Keyserver\Parser;

use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;

/**
 * Extracts PGP keys from various response formats.
 *
 * Handles HTML-wrapped keys, plain text keys, and various encoding quirks.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
class KeyExtractor
{
    /**
     * Extract a PGP key from response body.
     *
     * @param string $body Response body (may contain HTML or plain text)
     *
     * @return string ASCII-armored PGP key
     *
     * @throws KeyNotFoundException If no key found in response
     */
    public function extract(string $body): string
    {
        // Look for PGP key markers
        $start = strstr($body, '-----BEGIN');
        if ($start === false) {
            throw new KeyNotFoundException('No PGP key found in response');
        }

        // Find the end marker
        $endPos = strpos($start, '-----END');
        if ($endPos === false) {
            throw new KeyNotFoundException('Incomplete PGP key in response');
        }

        // Extract complete key block (including END line)
        // END line format: "-----END PGP PUBLIC KEY BLOCK-----"
        $length = $endPos + 34; // Length of "-----END PGP PUBLIC KEY BLOCK-----"

        return substr($start, 0, $length);
    }
}
