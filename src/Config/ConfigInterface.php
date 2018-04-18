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

namespace Mecanik\SanitiserX\Config;

interface ConfigInterface
{
    public function setFilterGETRequests($boolean);
    public function getFilterGETRequests();
    
    public function setOption($option, $value);
    public function getOption($option);
    public function hasOption($option);
    
    public function toArray();
}