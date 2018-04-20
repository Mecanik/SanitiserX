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

namespace Mecanik\SanitiserX\Service;

use Interop\Container\ContainerInterface;
use Zend\ServiceManager\Exception\ServiceNotCreatedException;
use Zend\ServiceManager\FactoryInterface;
use Zend\ServiceManager\ServiceLocatorInterface;
use Mecanik\SanitiserX\Config\ConfigInterface;
use Mecanik\SanitiserX\Config\SanitiserXConfig;

class SanitiserXConfigFactory implements FactoryInterface
{
    /**
     * Create SanitiserX configuration object (v3 usage).
     *
     * Uses "sanitiserx_config" section of configuration to seed a ConfigInterface
     * instance. By default, Mecanik\SanitiserX\Config\SanitiserXConfig will be used, but
     * you may also specify a specific implementation variant using the
     * "config_class" subkey.
     *
     * @param ContainerInterface $container
     * @param string $requestedName
     * @param null|array $options
     * @return ConfigInterface
     * @throws ServiceNotCreatedException if sanitiserx_config is missing, or an
     *     invalid config_class is used
     */
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {
        $config = $container->get('config');
        if (! isset($config['sanitiserx_config']) || ! is_array($config['sanitiserx_config'])) {
            throw new ServiceNotCreatedException(
                'Configuration is missing a "sanitiserx_config" key, or the value of that key is not an array'
            );
        }

        $class  = SanitiserXConfig::class;
        $config = $config['sanitiserx_config'];
        
        if (isset($config['config_class'])) {
            if (! class_exists($config['config_class'])) {
                throw new ServiceNotCreatedException(sprintf(
                    'Invalid configuration class "%s" specified in "config_class" sanitiserx configuration; '
                    . 'must be a valid class',
                    $config['config_class']
                ));
            }
            $class = $config['config_class'];
            unset($config['config_class']);
        }

        $sanitiserXConfig = new $class();
        if (! $sanitiserXConfig instanceof ConfigInterface) {
            throw new ServiceNotCreatedException(sprintf(
                'Invalid configuration class "%s" specified in "config_class" session configuration; must implement %s',
                $class,
                ConfigInterface::class
            ));
        }
        
        $sanitiserXConfig->setFilterGETRequests((int)$config['REQUESTS_FILTER_GET']);
        $sanitiserXConfig->setOption("LOG_UID", (int)$config['OPTIONS']['LOG']['LOG_UID']);
        $sanitiserXConfig->setOption("LOG_IP", (int)$config['OPTIONS']['LOG']['LOG_IP']);
        $sanitiserXConfig->setOption("LOG_DNS", (int)$config['OPTIONS']['LOG']['LOG_DNS']);
        $sanitiserXConfig->setOption("LOG_REFERER", (int)$config['OPTIONS']['LOG']['LOG_REFERER']);   
        $sanitiserXConfig->setOption("LOG_REQUEST_URL", (int)$config['OPTIONS']['LOG']['LOG_REQUEST_URL']);
        $sanitiserXConfig->setOption("LOG_REQUEST_METHOD", (int)$config['OPTIONS']['LOG']['LOG_REQUEST_METHOD']);
        
        return $sanitiserXConfig;
    }

    /**
     * Create and return a config instance (v2 usage).
     *
     * @param ServiceLocatorInterface $services
     * @param null|string $canonicalName
     * @param string $requestedName
     * @return ConfigInterface
     */
    public function createService(
        ServiceLocatorInterface $services,
        $canonicalName = null,
        $requestedName = ConfigInterface::class
    ) {
        return $this($services, $requestedName);
    }
}
