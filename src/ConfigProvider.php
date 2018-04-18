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

class ConfigProvider
{
    public function __invoke()
    {
        return [
            'dependencies' => $this->getDependencyConfig(),
        ];
    }

    public function getDependencyConfig()
    {
        return [
            'aliases' => [
                SanitiserXManager::class => ManagerInterface::class,
            ],
            'factories' => [
                Config\ConfigInterface::class => Service\SanitiserXConfigFactory::class,
                ManagerInterface::class => Service\SanitiserXManagerFactory::class,
            ],
        ];
    }
}