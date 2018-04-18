<?php
/**
 * SanitiserX
 *
 * Zend 2/3 Module that sanitises requests and inputs against XSS, SQL Injection and more
 *
 * @link
 * @copyright Copyright (c) 2018 Norbert Boros ( a.k.a Mecanik )
 * @license
 */

namespace Mecanik\SanitiserX;

use Mecanik\SanitiserX\Config\ConfigInterface as Config;

interface ManagerInterface
{
    public function setConfig(Config $config);
    public function getConfig();
}