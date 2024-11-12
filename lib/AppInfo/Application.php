<?php

declare(strict_types=1);

namespace OCA\RiskBasedAccountRecovery\AppInfo;

//Importing necessary classes for app framework, event dispatching and login event handling
use OCP\AppFramework\App;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\User\Events\UserLoggedInEvent;
use OCP\IDBConnection;

use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
use OCA\RiskBasedAccountRecovery\Listener\LoginListener;

//The main application class for the RiskBaseAccountRecovery App.
class Application extends App {
    public function __construct() {

        //Calling the parent constructor to register the app with nextcloud
        parent::__construct('RiskBasedAccountRecovery');
        // Retrieve the container
        $container = $this->getContainer();
        //Retrieve the event dispatcher from the app container to manage event listeners
        $dispatcher = $container->query(IEventDispatcher::class);

        //Retrieve the IDBConnection from the app container to enable database operations
        $dbConnection = $container->query(IDBConnection::class);

        //Initialize the DatabaseService class with the database connection
        $databaseService = new DatabaseService($dbConnection);
        //Call the createTable() method to create the 'rbaa_contextual_user_information' table if it does not exist
        $databaseService->createTable();

        // Registering the LoginListener as a service, and injecting the database connection
        $container->registerService(LoginListener::class, function($c) use ($dbConnection) {
            return new LoginListener($dbConnection);
        });

       // Registering the LoginListener to handle user login events. When a UserLoggedInEvent occurs, the handleLogin method of LoginListener will be triggered.
        $dispatcher->addListener(UserLoggedInEvent::class, function(UserLoggedInEvent $event) use ($container) {
            $container->get(LoginListener::class)->handleLogin($event);
        });

    }

}