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
                Config\ConfigInterface::class => Service\SanitiserXFactory::class
            ],
        ];
    }
}