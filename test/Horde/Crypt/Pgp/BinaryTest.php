<?php
/**
 * Tests for the PGP binary backend.
 *
 * @author     Michael Slusarz <slusarz@horde.org>
 * @category   Horde
 * @copyright  2015-2016 Horde LLC
 * @ignore
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package    Crypt
 * @subpackage UnitTests
 */
namespace Horde\Crypt\Pgp;
use \Horde_Crypt_Pgp_Backend_Binary;

class BinaryTest extends TestBase
{
    protected function _setUp()
    {
        $c = self::getConfig('CRYPT_TEST_CONFIG', __DIR__ . '/../');
        $gnupg = isset($c['gnupg'])
            ? $c['gnupg']
            : '/usr/bin/gpg';

        if (!is_executable($gnupg)) {
            $this->markTestSkipped(sprintf(
                'GPG binary not found at %s.',
                $gnupg
            ));
        }

        $backends = array(new Horde_Crypt_Pgp_Backend_Binary($gnupg));
        if (!empty($c['gnupg2'])) {
            $backends[] = new Horde_Crypt_Pgp_Backend_Binary($c['gnupg2']);
        }

        return $backends;
    }

}
