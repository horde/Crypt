<?php

/**
 * Horde_Crypt_Pgp tests.
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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Horde_Crypt;
use Horde_String;
use Exception;
use ReflectionClass;

abstract class TestBase extends TestCase
{
    private $_language;

    /* Returns the list of backends to test. */
    abstract protected function _setUp();

    /**
     * Get configuration from environment or config file.
     * Auto-detects test helpers when no config is present.
     */
    protected static function getConfig(string $env_key, string $config_path): array
    {
        // Try environment variable first
        $config_file = getenv($env_key);

        // Fall back to default config path
        if (!$config_file || !file_exists($config_file)) {
            $config_file = $config_path . 'conf.php';
        }

        // If config file exists, load it
        if (file_exists($config_file)) {
            return include $config_file;
        }

        // Auto-detect test helpers when no config present
        $config = [];

        // Try to find gpg binary
        $gpg_paths = ['/usr/bin/gpg', '/usr/local/bin/gpg', '/opt/homebrew/bin/gpg'];
        foreach ($gpg_paths as $path) {
            if (is_executable($path)) {
                $config['gnupg'] = $path;
                break;
            }
        }

        // Try gpg2 as well
        $gpg2_paths = ['/usr/bin/gpg2', '/usr/local/bin/gpg2', '/opt/homebrew/bin/gpg2'];
        foreach ($gpg2_paths as $path) {
            if (is_executable($path)) {
                $config['gnupg2'] = $path;
                break;
            }
        }

        return $config;
    }

    protected function setUp(): void
    {
        @date_default_timezone_set('GMT');
        $this->_language = getenv('LANGUAGE');
    }

    protected function tearDown(): void
    {
        putenv('LANGUAGE=' . $this->_language);
    }

    public static function backendProvider()
    {
        // Create a temporary instance to call _setUp()
        $reflection = new ReflectionClass(static::class);
        if ($reflection->isAbstract()) {
            return [];
        }

        $instance = $reflection->newInstanceWithoutConstructor();
        $pgp = [];
        try {
            $backends = $instance->_setUp();
            foreach ($backends as $backend) {
                $pgp[] = [Horde_Crypt::factory('Pgp', [
                    'backends' => [$backend],
                ])];
            }
        } catch (Exception $e) {
            // If setup fails, return empty array to skip tests
            return [];
        }
        return $pgp;
    }

    #[DataProvider("backendProvider")]
    public function testBug6601($pgp)
    {
        $data = $this->_getFixture('bug_6601.asc');

        putenv('LANGUAGE=C');
        $this->assertEquals(
            'Name:             Richard Selsky
Key Type:         Public Key
Key Creation:     04/11/08
Expiration Date:  04/11/13
Key Length:       1024 Bytes
Comment:          [None]
E-Mail:           rselsky@bu.edu
Hash-Algorithm:   pgp-sha1
Key ID:           0xF3C01D42
Key Fingerprint:  5912D91D4C79C6701FFF148604A67B37F3C01D42

',
            $pgp->pgpPrettyKey($data)
        );
    }

    /**
     * decrypt() message
     */
    #[DataProvider("backendProvider")]
    public function testPgpDecrypt($pgp)
    {
        // Encrypted data is in ISO-8859-1 format
        $crypt = $this->_getFixture('pgp_encrypted.txt');

        $decrypt = $pgp->decrypt($crypt, [
            'passphrase' => 'Secret',
            'privkey' => $this->_getPrivateKey(),
            'pubkey' => $this->_getPublicKey(),
            'type' => 'message',
        ]);

        $this->assertEquals(
            '0123456789012345678901234567890123456789
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
0123456789012345678901234567890123456789
!"$§%&()=?^´°`+#-.,*\'_:;<>|~\{[]}

',
            Horde_String::convertCharset($decrypt->message, 'ISO-8859-1', 'UTF-8')
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpDecryptSymmetric($pgp)
    {
        // Encrypted data is in ISO-8859-1 format
        $crypt = $this->_getFixture('pgp_encrypted_symmetric.txt');

        $decrypt = $pgp->decrypt($crypt, [
            'passphrase' => 'Secret',
            'type' => 'message',
        ]);

        $this->assertEquals(
            '0123456789012345678901234567890123456789
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
0123456789012345678901234567890123456789
!"$§%&()=?^´°`+#-.,*\'_:;<>|~\{[]}
',
            Horde_String::convertCharset($decrypt->message, 'ISO-8859-1', 'UTF-8')
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpEncrypt($pgp)
    {
        $clear = $this->_getFixture('clear.txt');

        $out = $pgp->encrypt($clear, [
            'recips' => ['me@example.com' => $this->_getPublicKey()],
            'type' => 'message',
        ]);

        $this->assertStringMatchesFormat(
            '-----BEGIN PGP MESSAGE-----
Version: GnuPG %s

%s
%s
%s
%s
%s
%s
%s
%s
%s
%s
=%s
-----END PGP MESSAGE-----',
            $out
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpEncryptSymmetric($pgp)
    {
        $clear = $this->_getFixture('clear.txt');

        $out = $pgp->encrypt($clear, [
            'passphrase' => 'Secret',
            'symmetric' => true,
            'type' => 'message',
        ]);

        $this->assertStringMatchesFormat(
            '-----BEGIN PGP MESSAGE-----
Version: GnuPG %s

%s
%s
%s
%s
=%s
-----END PGP MESSAGE-----',
            $out
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpEncryptedSymmetrically($pgp)
    {
        $this->assertFalse(
            $pgp->encryptedSymmetrically(
                $this->_getFixture('pgp_encrypted.txt')
            )
        );
        $this->assertTrue(
            $pgp->encryptedSymmetrically(
                $this->_getFixture('pgp_encrypted_symmetric.txt')
            )
        );
    }

    #[DataProvider("backendProvider")]
    public function testGetSignersKeyID($pgp)
    {
        $this->assertEquals(
            'BADEABD7',
            $pgp->getSignersKeyID($this->_getFixture('pgp_signed.txt'))
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpPacketInformation($pgp)
    {
        $out = $pgp->pgpPacketInformation($this->_getPublicKey());

        $this->assertArrayHasKey(
            'public_key',
            $out
        );
        $this->assertArrayNotHasKey(
            'secret_key',
            $out
        );
        $this->assertEquals(
            '1155291888',
            $out['public_key']['created']
        );
        $this->assertEquals(
            2,
            count($out['signature'])
        );
        $this->assertEquals(
            '7CA74426BADEABD7',
            $out['keyid']
        );

        $out = $pgp->pgpPacketInformation($this->_getPrivateKey());

        $this->assertArrayHasKey(
            'secret_key',
            $out
        );
        $this->assertArrayNotHasKey(
            'public_key',
            $out
        );
        $this->assertEquals(
            '1155291888',
            $out['secret_key']['created']
        );
        $this->assertEquals(
            2,
            count($out['signature'])
        );
        $this->assertEquals(
            '7CA74426BADEABD7',
            $out['keyid']
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpPacketSignature($pgp)
    {
        $out = $pgp->pgpPacketSignature(
            $this->_getPublicKey(),
            'me@example.com'
        );

        $this->assertEquals(
            '7CA74426BADEABD7',
            $out['keyid']
        );

        $out = $pgp->pgpPacketSignature(
            $this->_getPrivateKey(),
            'me@example.com'
        );

        $this->assertEquals(
            '7CA74426BADEABD7',
            $out['keyid']
        );

        $out = $pgp->pgpPacketSignature(
            $this->_getPrivateKey(),
            'foo@example.com'
        );

        $this->assertArrayNotHasKey(
            'keyid',
            $out
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpPacketSignatureByUidIndex($pgp)
    {
        $out = $pgp->pgpPacketSignatureByUidIndex(
            $this->_getPublicKey(),
            'id1'
        );

        $this->assertEquals(
            '7CA74426BADEABD7',
            $out['keyid']
        );

        $out = $pgp->pgpPacketSignatureByUidIndex(
            $this->_getPrivateKey(),
            'id1'
        );

        $this->assertEquals(
            '7CA74426BADEABD7',
            $out['keyid']
        );

        $out = $pgp->pgpPacketSignatureByUidIndex(
            $this->_getPrivateKey(),
            'id2'
        );

        $this->assertArrayNotHasKey(
            'keyid',
            $out
        );
    }

    #[DataProvider("backendProvider")]
    public function testPgpPrettyKey($pgp)
    {
        putenv('LANGUAGE=C');

        $this->assertEquals(
            'Name:             My Name
Key Type:         Public Key
Key Creation:     08/11/06
Expiration Date:  [Never]
Key Length:       1024 Bytes
Comment:          My Comment
E-Mail:           me@example.com
Hash-Algorithm:   pgp-sha1
Key ID:           0xBADEABD7
Key Fingerprint:  966F4BA9569DE6F65E8253977CA74426BADEABD7

',
            $pgp->pgpPrettyKey($this->_getPublicKey())
        );

        $this->assertEquals(
            'Name:             My Name
Key Type:         Private Key
Key Creation:     08/11/06
Expiration Date:  [Never]
Key Length:       1024 Bytes
Comment:          My Comment
E-Mail:           me@example.com
Hash-Algorithm:   pgp-sha1
Key ID:           0xBADEABD7
Key Fingerprint:  966F4BA9569DE6F65E8253977CA74426BADEABD7

',
            $pgp->pgpPrettyKey($this->_getPrivateKey())
        );
    }

    #[DataProvider("pgpGetFingerprintsFromKeyProvider")]
    public function testPgpGetFingerprintsFromKey($pgp, $expected, $key)
    {
        $this->assertEquals(
            $expected,
            $pgp->getFingerprintsFromKey($key)
        );
    }

    public static function pgpGetFingerprintsFromKeyProvider()
    {
        $fingerprints = [
            [
                [
                    '0xBADEABD7' => '966F4BA9569DE6F65E8253977CA74426BADEABD7',
                ],
                file_get_contents(dirname(__DIR__) . '/fixtures/pgp_public.asc'),
            ],
            [
                [
                    '0xBADEABD7' => '966F4BA9569DE6F65E8253977CA74426BADEABD7',
                ],
                file_get_contents(dirname(__DIR__) . '/fixtures/pgp_private.asc'),
            ],
        ];
        $args = self::backendProvider();
        foreach ($args as &$arg) {
            foreach ($fingerprints as $fingerprint) {
                $arg = array_merge($arg, $fingerprint);
            }
        }
        return $args;
    }

    #[DataProvider("backendProvider")]
    public function pgpPublicKeyMIMEPart($pgp)
    {
        $mime_part = $pgp->publicKeyMIMEPart($this->_getPublicKey());

        $this->assertEquals(
            'application/pgp-keys',
            $mime_part->getType()
        );

        $this->assertEquals(
            '-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG %s

mQGiBETcWvARBADNitbvsWy5/hhV+WcU2ttmtXkAj2DqJVgJdGS2RH8msO0roG5j
CQK/e0iMJki5lfdgxvxxWgStYMnfF5ftgWA7JV+BZUzJt12Lobm0zdENv2TqL2vc
xlPTmEGsvfPDTbY+Gr3jvuODboXat7bUn2E723WXPdh2A7KNNnLou7JF2wCgiKs/
RqNKM/Zm01PxLbQ+rs9ghd0D/jLUfJeYWySoDsvfO8e4UyDxDVTBLkkdw3XzLx1F
4SS/Cc2Z9yJuXiepzSH/G/vhdN5ROv12kJwA4FbwsFv5C1uCQleWiPngFixca9Nw
lAd2X2Cp0/4D2XRq1M9dEbcYdrgAuyzt2ZToj3aFaYNGwjfHoLqSngOu6/d3KD1d
i0b2A/9wnXo41kPwS73gU1Un2KKMkKqnczCQHdpopO6NjKaLhNcouRauLrgbrS5y
A1CW+nxjkKVvWrP/VFBmapUpjE1C51J9P0/ub8tRr7H0xHdTQyufv01lmfkjUpVF
n3GVf95l4seBFzD7r580aTx+dJztoHEGWrsWZTNJwo6IIlFOIbQlTXkgTmFtZSAo
TXkgQ29tbWVudCkgPG1lQGV4YW1wbGUuY29tPohgBBMRAgAgBQJE3FrwAhsjBgsJ
CAcDAgQVAggDBBYCAwECHgECF4AACgkQfKdEJrreq9fivACeLBcWErSQU4ZGQsje
dhwfdst9cLQAnRETpwmqt/XvcGFVsOE28MUrUzOGuQENBETcWvAQBADNgIJ4nDlf
gBOI/iqyNy08C9+MjxrqMylrj4TPn3rRk8wySr2myX+j9CML5EHOtsxANYeI9u7h
OF11n5Z8fDht/WGJrNR7EtRhNN6mkKsPaEuO3fhz6EgwJYReUVzDJbvnV2fRCvQo
EGaSntZGQaQzIzIL+/gMEFpEVRK1P2I3VwADBQP+K2Rmmkm3DonXFlUUDWWdhEF4
b7fy5/IPj41PSSOdo0IP4dprFoe15Vs9gWOYvzcnjy+BbOwhVwsjE3F36hf04od3
uTSM0dLS/xmpSvgbBh181T5c3W5aKT/daVhyxXJ4csxE+JCVKbaBubne0DPEuyZj
rYlL5Lm0z3VhNCcR0LyISQQYEQIACQUCRNxa8AIbDAAKCRB8p0Qmut6r16Y3AJ9h
umO5uT5yDcir3zwqUAxzBAkE4ACcCtGfb6usaTKnNXo+ZuLoHiOwIE4=
=GCjU
-----END PGP PUBLIC KEY BLOCK-----',
            $mime_part->getContents()
        );
    }

    #[DataProvider("backendProvider")]
    public function testGenerateKey($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');

        $expire = time() + 2 * 86400;
        $keys = $pgp->generateKey(
            'John Doe',
            'john@example.com',
            'secret',
            'Key Comment',
            4096,
            time() + 2 * 86400
        );
        // Key generation may take some time, so get the expiration date after
        // being finished.
        $this->assertStringStartsWith(
            '-----BEGIN PGP PUBLIC KEY BLOCK-----',
            $keys['public']
        );
        $this->assertStringStartsWith(
            '-----BEGIN PGP PRIVATE KEY BLOCK-----',
            $keys['private']
        );
        $info = $pgp->pgpPacketInformation($keys['private']);
        $this->assertEquals('John Doe', $info['signature']['id1']['name']);
        $this->assertEquals('john@example.com', $info['signature']['id1']['email']);
        $this->assertEquals('Key Comment', $info['signature']['id1']['comment']);
        $this->assertLessThan($expire + 30, $info['signature']['id1']['sig_' . $info['signature']['id1']['keyid']]['expires']);
        $this->assertGreaterThan($expire - 30, $info['signature']['id1']['sig_' . $info['signature']['id1']['keyid']]['expires']);
        $this->assertEquals(4096, $info['secret_key']['size']);
        $info = $pgp->pgpPacketInformation($keys['public']);
        $this->assertEquals('John Doe', $info['signature']['id1']['name']);
        $this->assertEquals('john@example.com', $info['signature']['id1']['email']);
        $this->assertEquals('Key Comment', $info['signature']['id1']['comment']);
        $this->assertLessThan($expire + 30, $info['signature']['id1']['sig_' . $info['signature']['id1']['keyid']]['expires']);
        $this->assertGreaterThan($expire - 30, $info['signature']['id1']['sig_' . $info['signature']['id1']['keyid']]['expires']);
        $this->assertEquals(4096, $info['public_key']['size']);
    }

    #[DataProvider("backendProvider")]
    public function testPgpSign($pgp)
    {
        $clear = $this->_getFixture('clear.txt');

        $out = $pgp->encrypt($clear, [
            'passphrase' => 'Secret',
            'privkey' => $this->_getPrivateKey(),
            'pubkey' => $this->_getPublicKey(),
            'type' => 'signature',
        ]);

        $this->assertStringMatchesFormat(
            '-----BEGIN PGP SIGNATURE-----
Version: GnuPG %s

%s
%s
=%s
-----END PGP SIGNATURE-----',
            $out
        );

        $out = $pgp->encrypt($clear, [
            'passphrase' => 'Secret',
            'privkey' => $this->_getPrivateKey(),
            'pubkey' => $this->_getPublicKey(),
            'sigtype' => 'cleartext',
            'type' => 'signature',
        ]);

        $this->assertStringMatchesFormat(
            '-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

0123456789012345678901234567890123456789
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
0123456789012345678901234567890123456789
!"$§%&()=?^´°`+#-.,*\'_:;<>|~\{[]}
-----BEGIN PGP SIGNATURE-----
Version: GnuPG %s

%s
%s
=%s
-----END PGP SIGNATURE-----',
            Horde_String::convertCharset($out, 'ISO-8859-1', 'UTF-8')
        );
    }

    #[DataProvider("backendProvider")]
    public function testDecryptSignature($pgp)
    {
        date_default_timezone_set('GMT');

        $out = $pgp->decrypt(
            $this->_getFixture('clear.txt'),
            [
                'pubkey' => $this->_getPublicKey(),
                'signature' => $this->_getFixture('pgp_signature.txt'),
                'type' => 'detached-signature',
            ]
        );

        $this->assertNotEmpty($out->result);

        $out = $pgp->decrypt(
            $this->_getFixture('pgp_signed.txt'),
            [
                'pubkey' => $this->_getPublicKey(),
                'type' => 'signature',
            ]
        );

        $this->assertNotEmpty($out->result);

        $out = $pgp->decrypt(
            $this->_getFixture('pgp_signed2.txt'),
            [
                'pubkey' => $this->_getPublicKey(),
                'type' => 'signature',
            ]
        );

        $this->assertNotEmpty($out->result);
    }

    #[DataProvider("backendProvider")]
    public function testVerifyPassphraseCorrect($pgp)
    {
        $this->assertTrue(
            $pgp->verifyPassphrase(
                $this->_getPublicKey(),
                $this->_getPrivateKey(),
                'Secret'
            )
        );
    }

    #[DataProvider("backendProvider")]
    public function testVerifyPassphraseIncorrect($pgp)
    {
        $this->assertFalse(
            $pgp->verifyPassphrase(
                $this->_getPublicKey(),
                $this->_getPrivateKey(),
                'Wrong'
            )
        );
    }

    #[DataProvider("backendProvider")]
    public function testGetPublicKeyFromPrivateKey($pgp)
    {
        $this->assertNotNull(
            $pgp->getPublicKeyFromPrivateKey($this->_getPrivateKey())
        );
    }

    #[DataProvider("backendProvider")]
    public function testDetectingDigestAlgoBug14814($pgp)
    {
        $fixture = $this->_getFixture('test_digest_algo.txt');
        $packetInfo = $pgp->pgpPacketInformation($fixture);
        $this->assertEquals(
            'pgp-sha512',
            $packetInfo['signature']['_SIGNATURE']['micalg']
        );
    }

    #[DataProvider("backendProvider")]
    #[DataProvider("backendProvider")]

    public function testMdcCorrect($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');
        $this->_testMdc($pgp, 'correct');
    }

    #[DataProvider("backendProvider")]
    #[DataProvider("backendProvider")]

    public function testMdcCorrectWithoutCrc($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');
        $this->_testMdc($pgp, 'correct-withoutcrc');
    }

    /**     */
    #[DataProvider("backendProvider")]
    public function testMdcWithoutMdc($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');
        $this->_testMdc($pgp, 'withoutmdc');
    }

    /**     */
    #[DataProvider("backendProvider")]
    public function testMdcManipulatedWithoutMdc($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');
        $this->_testMdc($pgp, 'manipulated-withoutmdc');
    }

    /**     */
    #[DataProvider("backendProvider")]
    public function testMdcWrongMdc($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');
        $this->_testMdc($pgp, 'wrongmdc');
    }

    /**     */
    #[DataProvider("backendProvider")]
    public function testMdcManipulated($pgp)
    {
        $this->expectException('Horde_Crypt_Exception');
        $this->_testMdc($pgp, 'manmessage');
    }

    protected function _testMdc($pgp, $fixture)
    {
        $crypt = $this->_getFixture('mdc/' . $fixture);

        $decrypt = $pgp->decrypt($crypt, [
            'passphrase' => '',
            'privkey' => $this->_getFixture('mdc/secret-key.gpg'),
            'pubkey' => $this->_getFixture('mdc/public-key.gpg'),
            'type' => 'message',
        ]);

        $this->assertStringEqualsFile(
            dirname(__DIR__) . '/fixtures/mdc/testmessage',
            $decrypt->message
        );
    }

    /* Helper methods. */

    protected function _getFixture($file)
    {
        return file_get_contents(dirname(__DIR__) . '/fixtures/' . $file);
    }

    protected function _getPrivateKey()
    {
        return $this->_getFixture('pgp_private.asc');
    }

    protected function _getPublicKey()
    {
        return $this->_getFixture('pgp_public.asc');
    }
}
