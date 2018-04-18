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

use Mecanik\SanitiserX\Exception;

/**
 * Standard SanitiserX configuration
 */
class StandardConfig implements \Mecanik\SanitiserX\Config\ConfigInterface
{
    /**
     * All options
     *
     * @var array
     */
    protected $options = [];
    
    /**
     * Set GET Requests Filtering ON/OFF
     *
     * @param  bool $boolean
     * @return StandardConfig
     * @throws Exception\InvalidArgumentException
     */
    public function setFilterGETRequests($boolean)
    {
        if (!is_bool($boolean)) {
            throw new Exception\InvalidArgumentException('Invalid Filter GET Requests; must be boolean.');
        }
        
        $this->setOption('REQUESTS_FILTER_GET', $boolean);

        return $this;
    }
    
    /**
     * Get Filter GET Requests status
     *
     * @return int
     */
    public function getFilterGETRequests()
    {
        if (! isset($this->options['REQUESTS_FILTER_GET'])) {
            throw new Exception\RuntimeException('This is weird; REQUESTS_FILTER_GET setting is missing.');
        }
        
        return $this->options['REQUESTS_FILTER_GET'];
    }
    
    /**
     * Set an individual option
     * 
     * Keys are normalized to uppercase.
     * 
     * @param  string $option
     * @param  mixed $value
     * @return StandardConfig
     */
    public function setOption($option, $value)
    {
        $option                 = strtoupper($option);
        $this->options[$option] = $value;
        
        return $this;
    }
    
    /**
     * Get an individual option
     * 
     * Keys are normalized to uppercase. 
     * 
     * Returns null for unfound options
     *
     * @param  string $option
     * @return mixed
     */
    public function getOption($option)
    {
        $option = strtoupper($option);
        if (array_key_exists($option, $this->options)) {
            return $this->options[$option];
        }
        
        return;
    }
    public function hasOption($option)
    {}

    public function toArray()
    {}

}