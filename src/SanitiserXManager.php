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

use Zend\Log\LogLevel;
use Zend\Log\Formatter;
use Zend\Log\Writer;
use Zend\Log\Logger;

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
    
    /**
     * Run all filters possible
     */
    const FILTER_TYPE_ALL = 6;
    
    public function __construct(Config\ConfigInterface $config = null, array $options = [])
    {
        $options = array_merge($this->extraOptions, $options);

        parent::__construct($config);
    }
    
    
    /**
     * Sanitise GET/POST input
     * 
     * Select which type, FILTER_TYPE_XSS = 1, FILTER_TYPE_CSRF = 2, FILTER_TYPE_SQLi = 3, FILTER_TYPE_RFI = 4, FILTER_TYPE_LFI = 5
     * 
     * If you select nothing, default FILTER_TYPE_XSS will be used.
     * 
     * @param  string $value
     * @param int $type
     * @return void
     */
    public function SanitiseInput($value = null, $type = self::FILTER_TYPE_XSS)
    {
        $this->WriteSanitiseInfoStartLog();
        
        switch($type)
        {
            case self::FILTER_TYPE_XSS: 
                
                $this->WriteSanitiseInfoPartialLog($value, "FILTER_TYPE_XSS");
                
                \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitize_xss($value);
                
                $this->WriteSanitiseInfoPhaseLog("SanitiserXEngine::sanitize_xss", $value);
                
                \Mecanik\SanitiserX\Engine\SanitiserXEngine::htmlspecialchars_unicode($value);
                
                $this->WriteSanitiseInfoPhaseLog("SanitiserXEngine::htmlspecialchars_unicode", $value);
                
                $this->WriteSanitiseInfoEndLog($value, "FILTER_TYPE_XSS");
                
            break;
                
            case self::FILTER_TYPE_CSRF:
                
            break;
                
            case self::FILTER_TYPE_SQLi:
                
                $this->WriteSanitiseInfoPartialLog($value, "FILTER_TYPE_SQLi");
                
                \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitise_sql($value);
                
                $this->WriteSanitiseInfoPhaseLog("SanitiserXEngine::sanitise_sql", $value);
                
            break;
                
            case self::FILTER_TYPE_RFI:
                
            break;
                
            case self::FILTER_TYPE_LFI:
                
            break;
            
            case self::FILTER_TYPE_ALL:
                
            break;
                
            default:
                    
                 break;
        }
        
        
       
    }
    
    /**
     * Helper function, made static so we can use it inside our Module.php
     * 
     * We pass on the values then to our InternalDispatchProcessor which is private.
     * 
     * @param string $key
     * @param string $value
     * @param array $settings
     */
    public static function DispatchProcessor($key, $value, $settings)
    {
        return self::InternalDispatchProcessor($key, $value, $settings);
    }
    
    /**
     * Our internal function, which we use to sanitise ALL the key:values we have in GET/POST
     * 
     * @param string $key
     * @param string $value
     * @param int $type
     */
    private function InternalDispatchProcessor($key, $value, $settings)
    {
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info( '----------------------------------------');
        
        if ($settings["OPTIONS"]["LOG"]["LOG_UID"] == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("UID: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::RandomToken(16)));
        }
        
        if ($settings["OPTIONS"]["LOG"]["LOG_IP"] == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Requesting IP: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_ip()));
        }
        
        if ($settings["OPTIONS"]["LOG"]["LOG_DNS"] == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("IP DNS: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_gethostbyaddr(\Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_ip())));
        }
        
        if ($settings["OPTIONS"]["LOG"]["LOG_REFERER"] == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Referer: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_referer()));
        }
        
        if ($settings["OPTIONS"]["LOG"]["LOG_REQUEST_URL"] == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Requested URL: %s", strip_tags($_SERVER['REQUEST_URI'])));
        }
        
        if ($settings["OPTIONS"]["LOG"]["LOG_REQUEST_METHOD"] == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Requested Method: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_request_method()));
        }
        
        if ($settings["REQUESTS_GET"]['AUTO_FILTER_XSS'] == 0) {
            $content = sprintf("[AUTO_FILTER_XSS] Cannot filter param: '%s' value: '%s'! Filter rule disabled.", $key, $value);
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::warn($content);
        } 
        else if ($settings["REQUESTS_GET"]['AUTO_FILTER_XSS'] == 1) {
            
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("[AUTO_FILTER_XSS] Filtering param: '%s' value: '%s'", $key, $value));
            
            $ct_rules = array('<', '>', 'alert', 'prompt');
            
            $check    = str_replace($ct_rules, '*', $value);
            
            if( $value != $check) {
                
                \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("[AUTO_FILTER_XSS] XSS attack in GET request!"));
                \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info( '----------------------------------------');
                
                return 1;
                
            } else {
                \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("[AUTO_FILTER_XSS] Now XSS found, continuing."));
            }

        }
        
        if ($settings["REQUESTS_GET"]['AUTO_FILTER_SQL'] == 0) {
            $content = sprintf("[AUTO_FILTER_SQL] Cannot filter param: '%s' value: '%s'! Filter rule disabled.", $key, $value);
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::warn($content);
        }
        else if ($settings["REQUESTS_GET"]['AUTO_FILTER_SQL'] == 1) {

            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("[AUTO_FILTER_SQL] Filtering param: '%s' value: '%s'", $key, $value));
            
            $stop = 0;
            
            $ct_rules = array('*/from/*', '*/insert/*', '+into+', '%20into%20', '*/into/*', ' into ', 'into', '*/limit/*', 'not123exists*', '*/radminsuper/*', '*/select/*', '+select+', '%20select%20', ' select ',  '+union+', '%20union%20', '*/union/*', ' union ', '*/update/*', '*/where/*');
            
            $check    = str_replace($ct_rules, '*', $value );
            
            if( $value != $check ) {
                $stop++;
            }
            
            if (preg_match('#\w?\s?union\s\w*?\s?(select|all|distinct|insert|update|drop|delete)#is', $value)) {
                $stop++;
            }
            
            if (preg_match('/([OdWo5NIbpuU4V2iJT0n]{5}) /', $value)) {
                $stop++;
            }
            
            if (strstr($value ,'*')) {
                $stop++;
            }
                
            if ($stop > 0) 
            { 
                \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("[AUTO_FILTER_SQL] SQL attack in GET request!"));
                \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info( '----------------------------------------');
                
                return 1;
                
            } else {
                \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("[AUTO_FILTER_SQL] No SQL attack detected, continuing."));
            }
        }
        
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info( '----------------------------------------');
        
        return 0;
    }
    
    /**
     * Function to write information log on single inputs of
     * @param string $content
     */
    private function WriteSanitiseInfoStartLog()
    {
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info( '----------------------------------------');
        
        if ($this->getConfig()->getOption('LOG_UID') == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("UID: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::RandomToken(16)));
        }
        
        if ($this->getConfig()->getOption('LOG_IP') == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Requesting IP: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_ip()));
        }
        
        if ($this->getConfig()->getOption('LOG_DNS') == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("IP DNS: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_gethostbyaddr(\Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_ip())));
        }
        
        if ($this->getConfig()->getOption('LOG_REFERER') == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Referer: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_referer()));
        }
        
        if ($this->getConfig()->getOption('LOG_REQUEST_URL') == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Requested URL: %s", strip_tags($_SERVER['REQUEST_URI'])));
        }
        
        if ($this->getConfig()->getOption('LOG_REQUEST_METHOD') == 1) {
            \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Requested Method: %s", \Mecanik\SanitiserX\Engine\SanitiserXEngine::sanitiserx_get_request_method()));
        }
    }
    
    private function WriteSanitiseInfoPartialLog($value, $type)
    {
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Sanitising: '%s' length: '%d' with method '%s'", $value, strlen($value), $type));
    }
    
    private function WriteSanitiseInfoPhaseLog($phase, $result)
    {
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Phase: '%s' Result: '%s' length: '%d'", $phase, $result, strlen($result)));
    }
    
    private function WriteSanitiseInfoEndLog($value, $type)
    {
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info(sprintf("Sanitised Result: '%s' length: '%d'", $value, strlen($value)));
        \Mecanik\SanitiserX\Helpers\SanitiserXLogger::info('----------------------------------------');
    }
}