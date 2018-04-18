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

namespace Mecanik\SanitiserX\Service;

use Interop\Container\ContainerInterface;
use Zend\ServiceManager\Exception\ServiceNotCreatedException;
use Zend\ServiceManager\FactoryInterface;
use Zend\ServiceManager\ServiceLocatorInterface;
use Mecanik\SanitiserX\Config\ConfigInterface;
use Mecanik\SanitiserX\Config\SanitiserXConfig;

class SanitiserXFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $config = $container->get('config');
        if (! isset($config['sanitiserx_config']) || ! is_array($config['sanitiserx_config'])) {
            throw new ServiceNotCreatedException('Configuration is missing a "sanitiserx_config" main key, or the value of that key is not an array.');
        }
        
        $class  = SanitiserXConfig::class;
        
        $sanitiserXConfig = new $class();
        
        if (! $sanitiserXConfig instanceof ConfigInterface) {
            throw new ServiceNotCreatedException(sprintf('Invalid configuration class "%s"; must implement %s', $class,ConfigInterface::class));
        }
        
        $sanitiserXConfig->setFilterGETRequests($config['sanitiserx_config']['REQUESTS_FILTER_GET']);

    }
    
    /**
     * Create and return a config instance (v2 usage).
     *
     * @param ServiceLocatorInterface $services
     * @param null|string $canonicalName
     * @param string $requestedName
     * @return ConfigInterface
     */
    public function createService(ServiceLocatorInterface $services, $canonicalName = null, $requestedName = ConfigInterface::class) 
    {
        return $this($services, $requestedName);
    }
}
