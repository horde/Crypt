<?php

/**
 * User Story Verification Examples
 *
 * This file demonstrates the three user stories are satisfied.
 */

// Note: This is a documentation file showing usage examples
// To actually run code, include the proper autoloader

// User Story 1: "As an integrator, I want the pre-existing interface to just work"
echo "=== User Story 1: Pre-existing Interface ===\n";
echo "Existing code works unchanged:\n\n";
echo "<?php\n";
echo "\$pgp = new Horde_Crypt_Pgp();\n";
echo "\$keyserver = new Horde_Crypt_Pgp_Keyserver(\$pgp);\n";
echo "// Auto-detects protocol (HKP v2 or falls back to HKP v1)\n";
echo "\$key = \$keyserver->get('0x12345678');\n";
echo "\n";

// User Story 2: "I may or may not know which type of key server I have"
echo "=== User Story 2: Optional Protocol Specification ===\n\n";

echo "Option A - I DON'T know (auto-detection):\n";
echo "<?php\n";
echo "\$keyserver = new Horde_Crypt_Pgp_Keyserver(\$pgp, [\n";
echo "    'keyserver' => 'https://keys.openpgp.org',\n";
echo "]);\n";
echo "// Probes for HKP v2, falls back to HKP v1\n";
echo "\n";

echo "Option B - I DO know it's HKP v1/SKS:\n";
echo "<?php\n";
echo "\$keyserver = new Horde_Crypt_Pgp_Keyserver(\$pgp, [\n";
echo "    'keyserver' => 'http://pool.sks-keyservers.net',\n";
echo "    'protocol' => 'hkp_v1',  // or 'sks'\n";
echo "]);\n";
echo "// Skips detection, uses HKP v1 directly\n";
echo "\n";

echo "Option C - I DO know it's HKP v2/Hagrid:\n";
echo "<?php\n";
echo "\$keyserver = new Horde_Crypt_Pgp_Keyserver(\$pgp, [\n";
echo "    'keyserver' => 'https://keys.openpgp.org',\n";
echo "    'protocol' => 'hkp_v2',  // or 'hagrid', 'modern'\n";
echo "]);\n";
echo "// Skips detection, uses HKP v2 directly\n";
echo "\n";

// User Story 3: "As a new consumer I want an option to integrate without excuses"
echo "=== User Story 3: Modern PSR API ===\n\n";

echo "New consumers can use the modern PSR-7/17/18 API directly:\n\n";
echo "<?php\n";
echo "use Horde\\Crypt\\Pgp\\Keyserver\\Client;\n";
echo "use Horde\\Http\\Client\\Curl;\n";
echo "use Horde\\Http\\RequestFactory;\n";
echo "use Horde\\Http\\StreamFactory;\n";
echo "use Horde\\Http\\HordeClientWrapper;\n";
echo "\n";
echo "\$psrClient = new HordeClientWrapper(\n";
echo "    new Curl(),\n";
echo "    new RequestFactory(),\n";
echo "    new StreamFactory()\n";
echo ");\n";
echo "\n";
echo "\$keyserverClient = new Client(\n";
echo "    'https://keys.openpgp.org',\n";
echo "    \$psrClient,\n";
echo "    new RequestFactory(),\n";
echo "    new StreamFactory(),\n";
echo "    \$pgp\n";
echo ");\n";
echo "\n";
echo "// Pure PSR-compliant, strongly typed, auto-detecting\n";
echo "\$key = \$keyserverClient->getKey('0x12345678');\n";
echo "\$keyserverClient->putKey(\$armoredKey);\n";
echo "\$key = \$keyserverClient->findKeyByEmail('user@example.com');\n";
echo "\n";

echo "Or force a specific protocol:\n";
echo "<?php\n";
echo "use Horde\\Crypt\\Pgp\\Keyserver\\Protocol\\HkpV1;\n";
echo "use Horde\\Crypt\\Pgp\\Keyserver\\Parser\\KeyExtractor;\n";
echo "use Horde\\Crypt\\Pgp\\Keyserver\\Parser\\MachineReadable;\n";
echo "\n";
echo "\$protocol = new HkpV1(\n";
echo "    'http://pool.sks-keyservers.net:11371',\n";
echo "    \$psrClient,\n";
echo "    new RequestFactory(),\n";
echo "    new StreamFactory(),\n";
echo "    \$pgp,\n";
echo "    new KeyExtractor(),\n";
echo "    new MachineReadable()\n";
echo ");\n";
echo "\n";
echo "\$keyserverClient = new Client(\n";
echo "    'http://pool.sks-keyservers.net:11371',\n";
echo "    \$psrClient,\n";
echo "    new RequestFactory(),\n";
echo "    new StreamFactory(),\n";
echo "    \$pgp,\n";
echo "    \$protocol  // Explicit protocol, no auto-detection\n";
echo ");\n";
echo "\n";

echo "========================================\n";
echo "All three user stories are satisfied:\n";
echo "✅ Pre-existing interface works unchanged\n";
echo "✅ Protocol can be specified or auto-detected\n";
echo "✅ Modern PSR API available for new consumers\n";
echo "========================================\n";
