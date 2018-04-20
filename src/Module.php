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

use Zend\ModuleManager\ModuleManager;
use Zend\Mvc\MvcEvent;

class Module
{    
    public function onBootstrap(MvcEvent $event)
    {
        // Get the Event manager
        $eventManager = $event->getApplication()->getEventManager();
        
        // Register the event listener method onDispatch
        $eventManager->attach(MvcEvent::EVENT_DISPATCH, [$this, 'onDispatch'], 100);
         
        // Here we match all routes for the application, and filter them.
        $em = $event->getApplication ()->getEventManager ();
        
        $em->attach ( MvcEvent::EVENT_ROUTE, function(MvcEvent $e) {
            
            $routeMatch = $e->getRouteMatch();
            
            foreach($routeMatch->getParams() as $key => $value) {
                //TODO
            }
            
        });
    }
    
    // Event listener method.
    public function onDispatch(MvcEvent $event)
    { 
        $config = $event->getApplication()->getServiceManager()->get('config');
       
        $settings = $config["sanitiserx_config"];
        
        $request = $event->getRequest();
        
        // If you want to automatically filter all GET requests
        if ($settings["REQUESTS_FILTER_GET"] != 0) {
            
            // Retrieving Query params is only possible if the request is an instance of \Zend\Http\Request
            if ($request instanceof \Zend\Http\Request) {
                
                // Make sure we only work on GET Requests
                if($request->getMethod() == 'GET') {
                    
                    // Query params - $queryParams is an instance of \Zend\Stdlib\Parameters
                    $queryParams = $request->getQuery();
                    
                    // Check if there is a query parameter, eg: ?example=12345
                    if (!empty($queryParams)) {
                        
                        // If yes, make it an array
                        $queryArray = $queryParams->toArray();
                        
                        // If we have a query parameter, make sure there is something in it... so we dont work on nothing!
                        if (!empty($queryArray)) {

                            // Let's iterate to see what parameters we have, and filter them!
                            foreach($queryArray as $key => $value) {
                                
                                // Pass parameters and values for processing
                                if(SanitiserXManager::DispatchProcessor($key, $value, $settings) == 1)
                                {
                                    // Get the current response
                                    $response = $event->getResponse();
                                    
                                    // Clear all headers
                                    $response->getHeaders()->clearHeaders();
                                    
                                    // Set Forbidden HTTP status code
                                    $response->setStatusCode(\Zend\Http\Response::STATUS_CODE_403);
                                    
                                    // Set a nice message!
                                    $response->setContent(\Mecanik\SanitiserX\Engine\SanitiserXEngine::block());
                                    
                                    return $response;
                                }
                            }
                        }
                    }                     
                }
            }
        }
        
        // If you want to automatically filter all POST requests
        if ($settings["REQUESTS_FILTER_POST"] != 0) {
            
            // Retrieveing Query and POST params is only possible if the request is an instance of \Zend\Http\Request
            if ($request instanceof \Zend\Http\Request) {

                // Make sure we only work on GET Requests
                if($request->getMethod() == 'POST') {
                    
                    // POST params - $postParams is an instance of \Zend\Stdlib\Parameters
                    $postParams  = $request->getPost()->toArray();
                    
                    // Check if there is a query parameter, eg: example: 12345
                    if (!empty($postParams)) {
                        
                        // If yes, make it an array
                        $postArray = $postParams->toArray();
                        
                        // If we have a query parameter, make sure there is something in it... so we dont work on nothing!
                        if (!empty($postArray)) {
                            
                            // Let's iterate to see what parameters we have, and filter them!
                            foreach($postArray as $key => $value) {
                                
                                // Pass parameters and values for processing
                                if(SanitiserXManager::DispatchProcessor($key, $value, $settings) == 1)
                                {
                                    // Get the current response
                                    $response = $event->getResponse();
                                    
                                    // Clear all headers
                                    $response->getHeaders()->clearHeaders();
                                    
                                    // Set Forbidden HTTP status code
                                    $response->setStatusCode(\Zend\Http\Response::STATUS_CODE_403);
                                    
                                    // Set a nice message!
                                    $response->setContent(\Mecanik\SanitiserX\Engine\SanitiserXEngine::block());
                                    
                                    return $response;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    public function getConfig()
    {
        $provider = new \Mecanik\SanitiserX\ConfigProvider();
        return [
            'service_manager' => $provider->getDependencyConfig(),
        ];
    }
}