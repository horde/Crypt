<?php

/**
 * Tests for accessing a public PGP keyserver.
 *
 * @author     Michael Slusarz <slusarz@horde.org>
 * @category   Horde
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package    Crypt
 * @subpackage UnitTests
 */

namespace Horde\Crypt;

use PHPUnit\Framework\TestCase;
use Horde_Crypt_Pgp_Keyserver;
use Horde_Crypt;

/**
 * @coversNothing
 */
class PgpKeyserverTest extends TestCase
{
    protected $_ks;
    protected $_gnupg;

    /**
     * Get configuration from environment or config file.
     */
    protected static function getConfig(string $env_key, string $config_path): array
    {
        // Try environment variable first
        $config_file = getenv($env_key);

        // Fall back to default config path
        if (!$config_file || !file_exists($config_file)) {
            $config_file = $config_path . '/conf.php';
        }

        // If config file exists, load it
        if (file_exists($config_file)) {
            return include $config_file;
        }

        // Return empty config
        return [];
    }

    protected function setUp(): void
    {
        $c = self::getConfig('CRYPT_TEST_CONFIG', __DIR__);
        $this->_gnupg = $c['gnupg']
            ?? '/usr/bin/gpg';

        if (!is_executable($this->_gnupg)) {
            $this->markTestSkipped(sprintf(
                'GPG binary not found at %s.',
                $this->_gnupg
            ));
        }

        $this->_ks = new Horde_Crypt_Pgp_Keyserver(
            Horde_Crypt::factory('Pgp', [
                'program' => $this->_gnupg,
            ])
        );
    }

    public function testKeyserverRetrieve()
    {
        // The default SKS pool now redirects to keys.openpgp.org
        // The key 4DE5B969 does not exist, so we expect KeyNotFoundException
        $this->expectException('Horde_Crypt_Exception');
        $this->expectExceptionMessage('Could not obtain public key from the keyserver');

        $this->_ks->get('4DE5B969');
    }

    public function testKeyserverRetrieveByEmail()
    {
        $this->expectException('Horde_Crypt_Exception');

        $this->assertEquals(
            '4DE5B969',
            $this->_ks->getKeyID('jan@horde.org')
        );

    }

    public function testBrokenKeyserver()
    {
        $this->expectException('Horde_Crypt_Exception');

        $ks = new Horde_Crypt_Pgp_Keyserver(
            Horde_Crypt::factory('Pgp', [
                'program' => $this->_gnupg,
            ]),
            ['keyserver' => 'http://pgp.key-server.io']
        );

        $this->assertEquals(
            '4DE5B969',
            $ks->getKeyID('jan@horde.org')
        );
    }
}
