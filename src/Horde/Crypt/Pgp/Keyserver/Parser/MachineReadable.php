<?php

declare(strict_types=1);

/**
 * Copyright 2013-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Pgp\Keyserver\Parser;

/**
 * Parses HKP machine-readable (mr) format responses.
 *
 * Machine-readable format uses colon-separated fields:
 * - info:version:count
 * - pub:keyid:algo:keylen:creationdate:expirationdate:flags
 * - uid:uidstring:creationdate:expirationdate:flags
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
class MachineReadable
{
    /**
     * Parse machine-readable format response.
     *
     * @param string $body Response body in machine-readable format
     *
     * @return array Array of keys with structure:
     *               [
     *                   [
     *                       'keyid' => string,
     *                       'algorithm' => int,
     *                       'length' => int,
     *                       'created' => int (timestamp),
     *                       'expires' => int|null (timestamp),
     *                       'flags' => string,
     *                       'uids' => [
     *                           ['email' => string, 'uid' => string, ...],
     *                           ...
     *                       ]
     *                   ],
     *                   ...
     *               ]
     */
    public function parse(string $body): array
    {
        $lines = explode("\n", $body);
        $keys = [];
        $currentKeyId = null;

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }

            $parts = explode(':', $line);
            $type = $parts[0] ?? '';

            if ($type === 'pub') {
                // pub:keyid:algo:keylen:creationdate:expirationdate:flags
                if (count($parts) < 7) {
                    continue; // Invalid line
                }

                [, $keyid, $algo, $length, $created, $expires, $flags] = $parts;

                // Skip expired keys
                if (!empty($expires) && (int) $expires <= time()) {
                    $currentKeyId = null;
                    continue;
                }

                $currentKeyId = $created; // Use timestamp as unique ID
                $keys[$currentKeyId] = [
                    'keyid' => $keyid,
                    'algorithm' => (int) $algo,
                    'length' => (int) $length,
                    'created' => (int) $created,
                    'expires' => !empty($expires) ? (int) $expires : null,
                    'flags' => $flags,
                    'uids' => [],
                ];
            } elseif ($type === 'uid' && $currentKeyId !== null) {
                // uid:uidstring:creationdate:expirationdate:flags
                if (count($parts) < 2) {
                    continue;
                }

                $uidString = $parts[1] ?? '';

                // Extract email from UID string (format: "Name <email@example.com>")
                $email = '';
                if (preg_match('/<([^>]+)>/', $uidString, $matches)) {
                    $email = $matches[1];
                }

                $keys[$currentKeyId]['uids'][] = [
                    'uid' => $uidString,
                    'email' => $email,
                ];
            }
        }

        return array_values($keys);
    }
}
