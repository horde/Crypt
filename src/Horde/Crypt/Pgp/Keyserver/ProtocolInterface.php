<?php

declare(strict_types=1);

/**
 * Copyright 2013-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Pgp\Keyserver;

use Horde\Crypt\Pgp\Keyserver\Exception\KeyAlreadyExistsException;
use Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException;
use Horde\Crypt\Pgp\Keyserver\Exception\ServerErrorException;

/**
 * Interface for keyserver protocol implementations.
 *
 * Defines the contract for different keyserver protocols (HKP v1/SKS, HKP v2, etc).
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
interface ProtocolInterface
{
    /**
     * Retrieve a PGP key by key ID.
     *
     * @param string $keyId The key ID to retrieve
     *
     * @return string ASCII-armored PGP public key
     *
     * @throws KeyNotFoundException If the key cannot be found
     * @throws ServerErrorException If the server returns an error
     */
    public function getKey(string $keyId): string;

    /**
     * Upload a PGP public key to the keyserver.
     *
     * @param string $armoredKey ASCII-armored PGP public key
     *
     * @throws KeyAlreadyExistsException If the key already exists
     * @throws ServerErrorException If the server returns an error
     */
    public function putKey(string $armoredKey): void;

    /**
     * Find a key ID by email address.
     *
     * @param string $email Email address to search for
     *
     * @return string Complete ASCII-armored PGP public key
     *
     * @throws KeyNotFoundException If no matching key is found
     * @throws ServerErrorException If the server returns an error
     */
    public function findKeyByEmail(string $email): string;

    /**
     * Check if this protocol is supported by the server.
     *
     * @return bool True if the protocol is supported
     */
    public function isSupported(): bool;
}
