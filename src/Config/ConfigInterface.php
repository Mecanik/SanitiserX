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

namespace Mecanik\SanitiserX\Config;

interface ConfigInterface
{
    public function setFilterGETRequests($int);
    public function getFilterGETRequests();
    
    public function setOption($option, $value);
    public function getOption($option);
    public function hasOption($option);
    
    public function toArray();
}