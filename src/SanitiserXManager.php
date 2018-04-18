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

class SanitiserXManager
{
    public function __construct(Config\ConfigInterface $config = null)
    {
            
        parent::__construct($config);
    }
    
    
    /**
     * @param  int $value
     * @return void
     */
    protected function sanitiseGET($value)
    {
        $config = $this->getConfig();
        if (! $config->getFilterGETRequests()) {
            return;
        }
        
       // Do filtering here
       // There is nothing here at the moment since I want to just setup the module to load properly in Zend 2 and 3 on packagist and then continue adding code.
    }
}