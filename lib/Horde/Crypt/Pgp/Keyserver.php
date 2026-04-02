<?php

/**
 * Copyright 2002-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @author   Michael Slusarz <slusarz@horde.org>
 * @category Horde
 * @license  http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package  Crypt
 */

/**
 * Provides methods to connect to a PGP keyserver.
 *
 * Connects to a public key server via HKP (Horrowitz Keyserver Protocol).
 * http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
 *
 * Refactored to use modern PSR-7/17/18 compliant implementation internally
 * while maintaining full backward compatibility.
 *
 * @author    Michael Slusarz <slusarz@horde.org>
 * @author    Ralf Lang <lang@b1-systems.de>
 * @category  Horde
 * @copyright 2002-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Crypt
 * @since     2.4.0
 */
class Horde_Crypt_Pgp_Keyserver
{
    /**
     * HTTP object.
     *
     * @var Horde_Http_Client
     */
    protected $_http;

    /**
     * Keyserver hostname.
     *
     * @var string
     */
    protected $_keyserver;

    /**
     * PGP object.
     *
     * @var Horde_Crypt_Pgp
     */
    protected $_pgp;

    /**
     * PSR-compliant keyserver client.
     *
     * @var Horde\Crypt\Pgp\Keyserver\Client
     */
    private $_client;

    /**
     * Constructor.
     *
     * @param Horde_Crypt_Pgp $pgp  A Horde_Crypt_Pgp object.
     * @param array $params         Optional parameters:
     * <pre>
     *   - http: (Horde_Http_Client) The HTTP client object to use.
     *   - keyserver: (string) The public PGP keyserver to use.
     *   - port: (integer) The public PGP keyserver port.
     *   - protocol: (string) Force specific protocol: 'hkp_v1' or 'hkp_v2'.
     *               If not specified, auto-detection is used.
     * </pre>
     */
    public function __construct($pgp, array $params = [])
    {
        $this->_pgp = $pgp;
        if (isset($params['http'])) {
            if (!($params['http'] instanceof Horde_Http_Client)) {
                throw new InvalidArgumentException('Argument is not a Horde_Http_Client instance');
            }
            $this->_http = $params['http'];
        } else {
            $this->_http = new Horde_Http_Client();
        }
        /* There is a broken key server software that returns HTML content
         * instead of plain text on arbitrary criteria. A User-Agent header is
         * one of those. */
        $this->_http->{'request.userAgent'} = '';
        $this->_keyserver = $params['keyserver']
            ?? 'http://pool.sks-keyservers.net';
        $this->_keyserver .= ':' . ($params['port'] ?? '11371');

        // Create PSR-compliant client wrapper
        $this->_client = $this->createPsrClient($params['protocol'] ?? null);
    }

    /**
     * Create PSR-compliant keyserver client.
     *
     * @param string|null $protocolName Force specific protocol or null for auto-detect
     *
     * @return Horde\Crypt\Pgp\Keyserver\Client
     */
    private function createPsrClient(?string $protocolName = null)
    {
        $requestFactory = new Horde\Http\RequestFactory();
        $streamFactory = new Horde\Http\StreamFactory();
        $responseFactory = new Horde\Http\ResponseFactory();
        $options = new Horde\Http\Client\Options();

        // Create PSR-18 compliant HTTP client wrapper
        $psrClient = new Horde\Http\HordeClientWrapper(
            new Horde\Http\Client\Curl($responseFactory, $streamFactory, $options),
            $requestFactory,
            $streamFactory
        );

        // If protocol specified, create it directly (skip auto-detection)
        $protocol = null;
        if ($protocolName !== null) {
            $protocol = match (strtolower($protocolName)) {
                'hkp_v1', 'hkpv1', 'sks' => new Horde\Crypt\Pgp\Keyserver\Protocol\HkpV1(
                    $this->_keyserver,
                    $psrClient,
                    $requestFactory,
                    $streamFactory,
                    $this->_pgp,
                    new Horde\Crypt\Pgp\Keyserver\Parser\KeyExtractor(),
                    new Horde\Crypt\Pgp\Keyserver\Parser\MachineReadable()
                ),
                'hkp_v2', 'hkpv2', 'modern', 'hagrid', 'hockeypuck' => new Horde\Crypt\Pgp\Keyserver\Protocol\HkpV2(
                    $this->_keyserver,
                    $psrClient,
                    $requestFactory,
                    $streamFactory,
                    $this->_pgp
                ),
                default => throw new InvalidArgumentException(
                    "Unknown protocol: $protocolName. Use 'hkp_v1', 'hkp_v2', or null for auto-detection."
                ),
            };
        }

        return new Horde\Crypt\Pgp\Keyserver\Client(
            $this->_keyserver,
            $psrClient,
            $requestFactory,
            $streamFactory,
            $this->_pgp,
            $protocol  // Pass protocol or null for auto-detection
        );
    }

    /**
     * Returns PGP public key data retrieved from a public keyserver.
     *
     * @param string $keyid  The key ID of the PGP key.
     *
     * @return string  The PGP public key.
     * @throws Horde_Crypt_Exception
     */
    public function get($keyid)
    {
        try {
            return $this->_client->getKey($keyid);
        } catch (Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException $e) {
            throw new Horde_Crypt_Exception(
                Horde_Crypt_Translation::t("Could not obtain public key from the keyserver."),
                0,
                $e
            );
        } catch (Horde\Crypt\Pgp\Keyserver\Exception\KeyserverException $e) {
            throw new Horde_Crypt_Exception($e->getMessage(), 0, $e);
        }
    }

    /**
     * Sends a PGP public key to a public keyserver.
     *
     * @param string $pubkey  The PGP public key
     *
     * @throws Horde_Crypt_Exception
     */
    public function put($pubkey)
    {
        try {
            $this->_client->putKey($pubkey);
        } catch (Horde\Crypt\Pgp\Keyserver\Exception\KeyAlreadyExistsException $e) {
            throw new Horde_Crypt_Exception(
                Horde_Crypt_Translation::t("Key already exists on the public keyserver.")
            );
        } catch (Horde\Crypt\Pgp\Keyserver\Exception\KeyserverException $e) {
            throw new Horde_Crypt_Exception($e->getMessage());
        }
    }

    /**
     * Returns the first matching key ID for an email address from a public
     * keyserver.
     *
     * @param string $address  The email address of the PGP key.
     *
     * @return string  The PGP key ID.
     * @throws Horde_Crypt_Exception
     */
    public function getKeyId($address)
    {
        try {
            $pubkey = $this->_client->findKeyByEmail($address);
            $sig = $this->_pgp->pgpPacketSignature($pubkey, $address);

            if (!empty($sig['keyid'])
                && (empty($sig['public_key']['expires'])
                || $sig['public_key']['expires'] > time())) {
                return substr($this->_pgp->getKeyIDString($sig['keyid']), 2);
            }
        } catch (Horde\Crypt\Pgp\Keyserver\Exception\KeyNotFoundException $e) {
            // Fall through to exception below
        } catch (Horde\Crypt\Pgp\Keyserver\Exception\KeyserverException $e) {
            throw new Horde_Crypt_Exception($e->getMessage());
        }

        throw new Horde_Crypt_Exception(
            Horde_Crypt_Translation::t("Could not obtain public key from the keyserver.")
        );
    }

    /**
     * Create the URL for the keyserver.
     *
     * @param string $uri    Action URI.
     * @param array $params  List of parameters to add to URL.
     *
     * @return Horde_Url  Keyserver URL.
     */
    protected function _createUrl($uri, array $params = [])
    {
        $url = new Horde_Url($this->_keyserver . $uri, true);
        return $url->add($params);
    }

}
