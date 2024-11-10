<?php

declare(strict_types=1);

namespace OCA\RiskBasedAccountRecovery\AppInfo;

//Importing necessary classes for app framework, event dispatching and login event handling
use OCP\AppFramework\App;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\User\Events\UserLoggedInEvent;

use OCA\RiskBasedAccountRecovery\Listener\LoginListener;

//The main application class for the RiskBaseAccountRecovery App.
class Application extends App {
    public function __construct() {

        //Calling the parent constructor to register the app with nextcloud
        parent::__construct('RiskBasedAccountRecovery');

        //Retrieve the event dispatcher from the app container to manage event listeners
        $dispatcher = $this->getContainer()->query(IEventDispatcher::class);

        // Register the LoginListener to handle user login events. When a UserLoggedInEvent occurs, the handleLogin method of LoginListener will be triggered.
        $dispatcher->addListener(UserLoggedInEvent::class, [new LoginListener(), 'handleLogin']);

    }

}