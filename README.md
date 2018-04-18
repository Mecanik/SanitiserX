# SanitiserX
Zend 2/3 Module that sanitises requests and inputs against XSS, SQL Injection and more


*Since this module is in active development, these instructions may change. Please check regularly for the latest updates, settings, features and implementation.*

## Zend Framework 3 instructions:

#### Create sanitiserx.local.php in PROJECT\config\autoload:

```
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
return [
    // More settings are being added, this is just basic
    'sanitiserx_config' => [
        'REQUESTS_FILTER_GET' => true, 
    ],
];
```

#### In module.config.php add the following:

```
use Mecanik\SanitiserX\SanitiserXManager;
use Mecanik\SanitiserX\Service\SanitiserXFactory;

'service_manager' => [
				'factories' => [
				    SanitiserXManager::class => SanitiserXFactory::class,
				],
],
```

#### Inject the service into your controller:

```
use Mecanik\SanitiserX\SanitiserXManager;

// This is just for example, MyController is your controller
class MyControllerFactory implements FactoryInterface
{
	public function __invoke(ContainerInterface $container, $requestedName, array $options = null)
	{
		$security = $container->get(SanitiserXManager::class);
    
		// Instantiate the controller and inject dependencies
		return new MyController($security);
	}
}
```
