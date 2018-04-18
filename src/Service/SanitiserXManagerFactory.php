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
use Mecanik\SanitiserX\SanitiserXManager;
use Mecanik\SanitiserX\ManagerInterface;

class SanitiserXManagerFactory implements FactoryInterface
{
    /**
     * @var array
     */
    protected $defaultManagerConfig = [];
    
    public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
    {        
        $config        = null;
        $managerConfig = $this->defaultManagerConfig;
        $options       = [];
        
        if ($container->has(ConfigInterface::class)) {
            $config = $container->get(ConfigInterface::class);
            if (! $config instanceof ConfigInterface) {
                throw new ServiceNotCreatedException(sprintf(
                    'SanitiserXManager requires that the %s service implement %s; received "%s"',
                    ConfigInterface::class,
                    ConfigInterface::class,
                    (is_object($config) ? get_class($config) : gettype($config))
                    ));
            }
        }
        
        // Get SanitiserX manager configuration, if any, and merge with default configuration
        if ($container->has('config')) {
            $configService = $container->get('config');
            if (isset($configService['sanitiserx_config'])
                && is_array($configService['sanitiserx_config'])
                ) {
                    $managerConfig = array_merge($managerConfig, $configService['sanitiserx_config']);
                }
                
                if (isset($managerConfig['OPTIONS'])) {
                    $options = $managerConfig['OPTIONS'];
                }
        }
        
        $managerClass = class_exists($requestedName) ? $requestedName : SanitiserXManager::class;
        if (! is_subclass_of($managerClass, ManagerInterface::class)) {
            throw new ServiceNotCreatedException(sprintf(
                'SanitiserXManager requires that the %s service implement %s',
                $managerClass,
                ManagerInterface::class
                ));
        }

        $manager = new $managerClass($config, $options);
            
        return $manager;
    }
    
    /**
     * Create a SanitiserXManager instance (v2 usage)
     *
     * @param ServiceLocatorInterface $services
     * @param null|string $canonicalName
     * @param string $requestedName
     * @return SanitiserXManager
     */
    public function createService(
        ServiceLocatorInterface $services,
        $canonicalName = null,
        $requestedName = SanitiserXManager::class
    ) {
        return $this($services, $requestedName);
    }
}
