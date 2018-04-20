<?php
/**
 * SanitiserX
 *
 * Zend 2/3 Module that sanitises requests and inputs against XSS, SQL Injection and more
 *
 * @link https://github.com/Mecanik/SanitiserX
 * @copyright Copyright (c) 2018 Norbert Boros ( a.k.a Mecanik )
 * @license https://github.com/Mecanik/SanitiserX/blob/master/LICENSE
 */

namespace Mecanik\SanitiserX;

use Mecanik\SanitiserX\Config\ConfigInterface as Config;

interface ManagerInterface
{
    public function setConfig(Config $config);
    public function getConfig();
    
    public function SanitiseInput($value = null, $type = self::FILTER_TYPE_XSS);
}