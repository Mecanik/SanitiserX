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

namespace Mecanik\SanitiserX\Helpers;

use Zend\Log\Formatter;
use Zend\Log\Writer;
use Zend\Log\Logger;

/**
 * Very ugly logger from my opinion...
 * 
 * @author NBoros
 *
 */
class SanitiserXLogger
{
    public static function __callStatic($method, $args)
    {
        //Check if the directory already exists.
        if(!is_dir('./data/sanitiserX')){
            //Directory does not exist, so lets create it.
            mkdir('./data/sanitiserX', 0755, true);
        }
        
        $logger = new Logger();
        
        $writer = new Writer\Stream('./data/sanitiserX/'.date('Y-m-d').'-security.log');
        
        $formatter = new Formatter\Simple('[SanitiserX] [%timestamp%] [%priorityName%] %message% %extra%');
        
        $writer->setFormatter($formatter);
        
        $logger->addWriter($writer);
        
        return $logger->$method($args[0]);
    }
}

