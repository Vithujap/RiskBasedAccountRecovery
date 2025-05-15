<?php

declare(strict_types=1);

namespace OCA\RiskBasedAccountRecovery\AppInfo;

//Importing necessary classes for app framework, event dispatching and login event handling
use OCP\AppFramework\App;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\PostLoginEvent;
use OCP\IDBConnection;
use OCP\User\Events\BeforePasswordUpdatedEvent;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUserSession;

use OCP\IUserManager;
use OCP\Security\ISecureRandom;
use OCP\Mail\IMailer;
use OCP\IConfig;

use OCP\AppFramework\Http\Events\BeforeLoginTemplateRenderedEvent;
use OCP\AppFramework\TemplateResponse;



use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
use OCA\RiskBasedAccountRecovery\Service\RiskAssessmentService;
use OCA\RiskBasedAccountRecovery\Service\ChallengeService;

use OCA\RiskBasedAccountRecovery\Listener\LoginListener;


use OCA\RiskBasedAccountRecovery\Controller\PasswordResetController;
use OCA\RiskBasedAccountRecovery\Controller\HelloWorldController;


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

        $request = $container->query(IRequest::class);

        //Initialize the DatabaseService class with the database connection
        $databaseService = new DatabaseService($dbConnection);
        //Call the createTable() method to create the 'rbaa_contextual_user_information' table if it does not exist
        $databaseService->createTables();
    
        //Register LoginListenr
        $container->registerService(LoginListener::class, function($c) use ($dbConnection) {
            return new LoginListener($dbConnection);
        });

       // Adding listener to the LoginListener to handle user login events. When a UserLoggedInEvent occurs, the handleLogin method of LoginListener will be triggered.
        $dispatcher->addListener(UserLoggedInEvent::class, function(UserLoggedInEvent $event) use ($container) {
            $container->get(LoginListener::class)->handleLogin($event);
        });

        //Adding a listener to Before the login website/template renderes, and changes the default forgot password link
        $dispatcher->addListener(BeforeLoginTemplateRenderedEvent::class, function (BeforeLoginTemplateRenderedEvent $event) {
            //Changing the forgotten pasword link to our own RBAR link.
            \OCP\Util::addScript('RiskBasedAccountRecovery', 'passwordRedirect'); 
        });

        //Retrieving the user session
        $userSession = $container->get(IUserSession::class);
        //Checking if the user is logged in. If so, we will add the script to show the security question setup if not established.
        if ($userSession->isLoggedIn()) {
            //Get the username
            $username = $userSession->getUser()->getUID();
            //If the user hasnt established security questions, show it.
            if (!$databaseService->hasSecurityQuestions($username)) {
                \OCP\Util::addScript('RiskBasedAccountRecovery', 'securityQuestionSetup');
            }
        }
    }


}