<?php

namespace Test;

// Load Composer autoloader
require_once __DIR__ . '/../vendor/autoload.php';

// Include Nextcloud's core autoloader
require_once '/var/www/nextcloud/lib/base.php'; // Path to Nextcloud's base.php

use PHPUnit\Framework\TestCase;

// Define AppTestCase
class AppTestCase extends TestCase {
    // Optional setup logic
}


