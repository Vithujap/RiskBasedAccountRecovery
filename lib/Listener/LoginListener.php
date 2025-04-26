<?php 

namespace OCA\RiskBasedAccountRecovery\Listener;

use OCP\User\Events\UserLoggedInEvent;
use OCP\IDBConnection;
use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
use OCA\RiskBasedAccountRecovery\Service\DeviceInfoService;
use OCA\RiskBasedAccountRecovery\Service\GeoLocationService;
//use OCP\Authentication\TwoFactorAuth\IManager as TwoFactorManager;


/**
 * LoginListener class is called when user login events are triggered and logs the contextual information of the user such as IP address, browser, operating system, and country,
 */
class LoginListener {
    //Holds the database connection instance
    private $dbConnection;
    //private $twoFactorManager;

    /**
     * Constructor for LoginListener
     * 
     * @param IDBConnection $dbConnection is the dependency injection for the database connection,
     */
    public function __construct(IDBConnection $dbConnection) {
        $this->dbConnection = $dbConnection;
        //$this->twoFactorManager = $twoFactorManager;
    }
        
        
    /**
     * This method handles user login events by retrieving the logging-in user's contextual information like ip address, browser, OS, etc and storing it into the database.
     * 
     * @param UserLoggedInEvent $event The login event object, containing user information.
     */
    public function handleLogin(UserLoggedInEvent $event) {
        try {
            //Retrieve the user id from the login event
            $username = $event->getUser()->getUID();

            // Capture the IP address and the user agent from server varaibles, with "unknown" as fallback
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

            //Initializing DeviceInfoService class to parse and retrieve browser and operating system information
            $deviceInfo = new DeviceInfoService($userAgent);
            $browser = $deviceInfo->getBrowser();
            $os = $deviceInfo->getOS();

            //Initializing GeoLocationService class to obtain the country name based on the IP addres
            $geoService = new GeoLocationService();
            $country = $geoService->getCountryNameFromIP($ipAddress);

            // Insert the collected contextual info into the database
            $dbService = new DatabaseService($this->dbConnection);
            $dbService->insertContextualInformation($username, $ipAddress, $country, $browser, $os);
        } 
        catch (\Throwable $e)  {
            //Logging any unexpected errors that occurs during the handling of login process.
            error_log("LoginListener: Failed to handle the login - {$e->getMessage()}");
        }
    }
    
}