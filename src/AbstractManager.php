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
use Mecanik\SanitiserX\ManagerInterface as Manager;

/**
 * Base ManagerInterface implementation
 *
 * Defines common constructor logic and getters for Storage and Configuration
 */
abstract class AbstractManager implements Manager
{
    /**
     * @var Config
     */
    protected $config;
    
    
    /**
     * Default configuration class to use when no configuration provided
     * @var string
     */
    protected $defaultConfigClass = 'Mecanik\SanitiserX\SanitiserXConfig';
    

    /**
     * Constructor
     *
     * @param  Config|null      $config
     * @throws Exception\RuntimeException
     */
    public function __construct(
        Config $config = null
    ) {
        // init config
        if ($config === null) {
            if (! class_exists($this->defaultConfigClass)) {
                throw new Exception\RuntimeException(sprintf(
                    'Unable to locate config class "%s"; class does not exist',
                    $this->defaultConfigClass
                ));
            }

            $config = new $this->defaultConfigClass();

            if (! $config instanceof Config) {
                throw new Exception\RuntimeException(sprintf(
                    'Default config class %s is invalid; must implement %s\Config\ConfigInterface',
                    $this->defaultConfigClass,
                    __NAMESPACE__
                ));
            }
        }
        
        $this->config = $config;
    }

    /**
     * Set configuration object
     *
     * @param  Config $config
     * @return AbstractManager
     */
    public function setConfig(Config $config)
    {
        $this->config = $config;
        return $this;
    }

    /**
     * Retrieve configuration object
     *
     * @return Config
     */
    public function getConfig()
    {
        return $this->config;
    }
}
