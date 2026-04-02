<?php

declare(strict_types=1);

/**
 * Copyright 2013-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 */

namespace Horde\Crypt\Pgp\Keyserver\Exception;

/**
 * Exception thrown when the keyserver returns an error.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 */
class ServerErrorException extends KeyserverException {}
