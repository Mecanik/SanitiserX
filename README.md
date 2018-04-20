# SanitiserX
Zend 2/3 Module that sanitises requests and inputs against XSS (Cross-Site Scripting), CSRF (Cross-Site Request Forgery), RFI (Remote File Inclusion), LFI (Local File Inclusion), SQLi (SQL Injection) and more...

*Since this module is in active development, these instructions may change. Please check regularly for the latest updates, settings, features and implementation.*


## Zend Framework 3 instructions:

#### Install the module with composer:

```
composer require mecanik/sanitiser-x
```

#### Create *sanitiserx.local.php* in *PROJECT\config\autoload*:

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
        
        'REQUESTS_FILTER_GET' => 1, 
        'REQUESTS_GET' => [
            'AUTO_FILTER_XSS' => 1,
            'AUTO_FILTER_SQL' => 1,
        ],
        
        'REQUESTS_FILTER_POST'=> 1,
        'REQUESTS_POST' => [
            'AUTO_FILTER_XSS' => 1,
            'AUTO_FILTER_SQL' => 1,
        ],
        
        'REQUESTS_FILTER_COOKIES'=> 0,
        'REQUESTS_COOKIES' => [
            'AUTO_FILTER_XSS' => 0,
            'AUTO_FILTER_SQL' => 0,
        ],
        
        'REQUESTS_FILTER_HTTP_USER_AGENT'=> 0,
        'REQUESTS_FILTER_HTTP_REFERER'=> 0,
        'REQUESTS_FILTER_HTTP_PATH_INFO'=> 0,
        'REQUESTS_FILTER_HTTP_PATH_TRANSLATED'=> 0,
        'REQUESTS_FILTER_HTTP_PHP_SELF'=> 0,
        
        'OPTIONS' => [
            'LOG' => [
                'LOG_UID' => 1,
                'LOG_IP' => 1,
                'LOG_DNS' => 1,
                'LOG_REFERER' => 1,
                'LOG_REQUEST_URL' => 1,
                'LOG_REQUEST_METHOD' => 1,
            ],
        ]
    ],
    
];
```

#### In *module.config.php* add the following:

```
use Mecanik\SanitiserX\SanitiserXManager;
use Mecanik\SanitiserX\Service\SanitiserXManagerFactory;

'service_manager' => [
				'factories' => [
				    SanitiserXManager::class => SanitiserXManagerFactory::class,
				],
],
```

#### Load the module in *PROJECT\config\modules.config.php*:

```
'Mecanik\SanitiserX',
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
#### And use the functions in your controller:

```
use Mecanik\SanitiserX\SanitiserXManager;

// This is just for example, MyController is your controller
class MyController extends AbstractActionController
{   
    /**
     * Mecanik's Sanitiser Modules
     * @var SanitiserXManager
     */
    private $security;
    
    /**
     * Constructor. Its purpose is to inject dependencies into the controller.
     */
    public function __construct($security)
    {
    	$this->security = $security;
   	 }
   	 
   	 public function someAction()
   	 {
   	 	$this->security->SanitiseInput($_GET['username'], 1);
   	 }
}

```

### Current filter options

```

// Cross-Site Scripting
// FILTER_TYPE_XSS = 1
$this->security->SanitiseInput($_GET['username'], 1);   

//Cross-Site Request Forgery
//FILTER_TYPE_CSRF = 2

$this->security->SanitiseInput($_GET['username'], 2);   

//SQL Injection
//FILTER_TYPE_SQLi = 3

$this->security->SanitiseInput($_GET['username'], 3);   

//Remote File Inclusion
//FILTER_TYPE_RFI = 4

$this->security->SanitiseInput($_GET['username'], 4);   

//Local File Inclusion
//FILTER_TYPE_LFI = 5

$this->security->SanitiseInput($_GET['username'], 5);   

//All filters possible
//FILTER_TYPE_ALL = 6

$this->security->SanitiseInput($_GET['username'], 6);
    
```