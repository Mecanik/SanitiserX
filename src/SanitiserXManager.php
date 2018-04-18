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

class SanitiserXManager extends AbstractManager
{
    /**
     * @var array extra options for future
     */
    protected $extraOptions = [];
    
    /** 
     * Cross-Site Scripting
     */
    const FILTER_TYPE_XSS = 1;
    
    /**
     * Cross-Site Request Forgery
     */
    const FILTER_TYPE_CSRF = 2;
    
    /**
     * SQL Injection
     */
    const FILTER_TYPE_SQLi = 3;
    
    /**
     * Remote File Inclusion
     */
    const FILTER_TYPE_RFI = 4;
    
    /**
     * Local File Inclusion
     */
    const FILTER_TYPE_LFI = 5;
    
    public function __construct(Config\ConfigInterface $config = null, array $options = [])
    {
        $options = array_merge($this->extraOptions, $options);
        
        parent::__construct($config);
    }
    
    
    /**
     * Sanitise GET input
     * 
     * Select which type, FILTER_TYPE_XSS = 1, FILTER_TYPE_CSRF = 2, FILTER_TYPE_SQLi = 3, FILTER_TYPE_RFI = 4, FILTER_TYPE_LFI = 5
     * 
     * If you select nothing, default FILTER_TYPE_XSS will be used.
     * 
     * @param  string $value
     * @param int $type
     * @return void
     */
    public function sanitiseGET($value = null, $type = self::FILTER_TYPE_XSS)
    {
        $config = $this->getConfig();
        
        if ($config->getFilterGETRequests() == 0) {
           return;
        }
        
        switch($type)
        {
            case self::FILTER_TYPE_XSS: 
                \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitize_xss($value);
                \Mecanik\SanitiserX\Engine\SanitiserXEngine::htmlspecialchars_unicode($value);
                break;
                
            case self::FILTER_TYPE_CSRF:
                
                break;
                
            case self::FILTER_TYPE_SQLi:
                
                break;
                
            case self::FILTER_TYPE_RFI:
                
                break;
                
            case self::FILTER_TYPE_LFI:
                
                break;
               
            default:
                    
                    break;
        }
       
    }
    
    
    
    
    
}