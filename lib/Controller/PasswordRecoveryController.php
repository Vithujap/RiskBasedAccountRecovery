<?php

namespace OCA\RiskBasedAccountRecovery\Controller;

use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IUserManager;
use OCP\IDBConnection;
use OCP\Http\Client\IClientService;
use OCP\IURLGenerator;
use OCP\Mail\IMailer;
use OCP\IConfig;
use OCP\Security\ISecureRandom;

use OCA\RiskBasedAccountRecovery\Service\RiskAssessmentServiceV2;
use OCA\RiskBasedAccountRecovery\Service\GeoLocationService;
use OCA\RiskBasedAccountRecovery\Service\DeviceInfoService;
use OCA\RiskBasedAccountRecovery\Service\ChallengeService;
use OCA\RiskBasedAccountRecovery\Service\PasswordRecoveryService;
use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
//This class is the controller class for the Password Recovery process in the frontend.
class PasswordRecoveryController extends Controller {

    private $userManager;
    private $dbConnection;
    private $clientService;
    private $urlGenerator;
    private $mailer;
    private $config;
    private $secureRandom;
    private $challengeService; 
    private $passwordRecoveryService;
    private DatabaseService $databaseService;
    private $riskAssessmentService;
    /**
     * Constructor to inject dependencies.
     */
    public function __construct(
        $appName,
        IRequest $request,
        IUserManager $userManager,
        IDBConnection $dbConnection,
        IClientService $clientService,
        IURLGenerator $urlGenerator,
        IMailer $mailer,
        IConfig $config,
        ISecureRandom $secureRandom,
        ChallengeService $challengeService,
        PasswordRecoveryService $passwordRecoveryService
    ) {
        parent::__construct($appName, $request);
        $this->userManager = $userManager;
        $this->dbConnection = $dbConnection;
        $this->clientService = $clientService;
        $this->urlGenerator = $urlGenerator;
        $this->mailer = $mailer;
        $this->config = $config;
        $this->secureRandom = $secureRandom;
        $this->challengeService = $challengeService;
        $this->passwordRecoveryService = $passwordRecoveryService;
        $this->databaseService = new DatabaseService($this->dbConnection);
        $this->riskAssessmentService = new RiskAssessmentServiceV2($this->dbConnection);
    }

    /**
     * @NoCSRFRequired
     * @PublicPage
     * @NoAdminRequired
     * 
     * Shows and renders the password recovery form template.
     */
    public function showRecoveryForm() {        
        // Use TemplateResponse to render the password recovery form template
        return new TemplateResponse('RiskBasedAccountRecovery', 'passwordRecoveryForm', [], 'guest');
    }
    /**
     * @NoCSRFRequired
     * @PublicPage
     * @NoAdminRequired
     * 
     * Shows and renders the Update Password Form, which is shown after the user clicks on the reset link
     */
    public function showUpdatePasswordForm($urlToken, $username) {
        // Check if the token is valid
        if (!$this->passwordRecoveryService->validateResetToken($urlToken, $username)) {
            // Pass an error message to the template and do not show the form
            return new TemplateResponse(
                'RiskBasedAccountRecovery', 
                'passwordUpdateForm', 
                ['error' => 'Invalid or expired token. Please try again.'], 
                'guest'
            );
        }
    
        // Pass no error and show the form
        return new TemplateResponse('RiskBasedAccountRecovery', 'passwordUpdateForm', [
            'urlToken' => $urlToken,
            'username' => $username,
        ], 'guest');
    }
    /**
     * @NoCSRFRequired
     * @PublicPage
     * @NoAdminRequired
     * 
     * Handles the updating of the user password once the user enters the password they wish to update to
     */
    public function updateUserPassword() {
        $username = $this->request->getParam('username');
        $newPassword = $this->request->getParam('password');
        $urlToken = $this->request->getParam('urlToken');
    
        try {
            // Validate the reset token
            if (!$this->passwordRecoveryService->validateResetToken($urlToken, $username)) {
                throw new \Exception("Invalid or expired token");
            }
        
            // Get the user and update the password
            $user = $this->userManager->get($username);
            if (!$user) {
                throw new \Exception("User not found");
            }
        
            // Update the user's password
            $user->setPassword($newPassword);
        
            // Only remove the token AFTER all operations are successful
            $this->passwordRecoveryService->removeResetToken($username);
        
            // Respond with success
            http_response_code(200);
            return new TemplateResponse(
                'RiskBasedAccountRecovery', 
                'passwordUpdateForm', 
                ['success' => 'The password has been updated! Go to login page!'], 
                'guest'
            );
        
        } catch (\Exception $e) { //Handles error
            http_response_code(500);
            return new TemplateResponse(
                'RiskBasedAccountRecovery', 
                'passwordUpdateForm', 
                ['error' => 'Failed to update password. Error: ' . $e->getMessage()], 
                'guest'
            );
        }
    
        // Render error if token is invalid or expired
        return new TemplateResponse(
            'RiskBasedAccountRecovery', 
            'passwordUpdateForm', 
            ['error' => 'Invalid or expired token. Please try again.'], 
            'guest'
        );
    }
    /**
     * @NoCSRFRequired
     * @PublicPage
     * @NoAdminRequired
     * 
     * Handles the account recovery process once an email or username has been submitted.
     * In cases of people entering the wrong username/email, they will still continue to go through the recovery process
     *  - This is done to not give any "hints" to malicious users that the username or email entered is not assosiated with a valid account
     */
    public function startRecovery() {
        try {
            $emailOrUsername = $this->request->getParam('email_or_username');
            //Initializing username as empty string
            $username = "";
            $userExists = false;
        
            // Validate empty input
            if (empty($emailOrUsername)) {
                return new TemplateResponse('RiskBasedAccountRecovery', 'passwordRecoveryForm', ['error' => "Username or email is required."], 'guest');
            }
        
            //If the string contains @, we assume its an email address. Else username
            if (str_contains($emailOrUsername, "@")) {
                $username = $this->databaseService->getUidByEmail($emailOrUsername);
                $userExists = $username !== null;
            }
            else { //assuming it is a username
                $userExists = $this->userManager->userExists($emailOrUsername);
                $username = $userExists ? $emailOrUsername : null;
            }
        
            //If user exists, try to get email
            if ($userExists && $username !== null) {
                $user = $this->userManager->get($username);
                $username = $user ? $user->getUID() : null;
                // Fetch email associated with the user
                $email = $this->config->getUserValue($username, 'settings', 'email', '');
            }
            //If the user dosnt exist, a fake username and will be generated to continue with the recovery flow and not give any hints
            if (!$userExists || empty($email)) {
                $username = "guest_" . bin2hex(random_bytes(5));
                $email = "dummyEmail@rbar.com";
            }
        
            // Determine risk level
            $riskLevel = $this->handleRecoveryAttempt($username);
    
            // Generate a challenge
            $challengeData = $this->challengeService->generateChallenge($riskLevel, $username, $email);

            if (isset($challengeData['type']) && $challengeData['type'] === 'error') {
                return new TemplateResponse(
                    'RiskBasedAccountRecovery', 
                    'passwordUpdateForm', 
                    ['error' => $challengeData['error'] ?? 'Challenge generation failed.'], 
                    'guest'
                );
            }
            
            //Shows the challenge form to the user
            return new TemplateResponse(
                'RiskBasedAccountRecovery',
                'challengeForm',
                $challengeData,
                'guest'
            );
        }
        catch (\Throwable $e) {
            error_log("StartRecovery error:" . $e->getMessage());
            return new TemplateResponse(
                'RiskBasedAccountRecovery', 
                'challengeForm', 
                ['error' => 'An unexpected error occured. Please try again'], 
                'guest'
            );
        }
    }

    /**
     * Handle the account recovery attempt by assessing risk based on the provided context
     * @param string $username The username of the account.
     */
    private function handleRecoveryAttempt($username) {
        try {
            // Fetch current recovery context
            $ipAddress = $this->request->getRemoteAddress() ?? 'unknown';
            $userAgent = $this->request->getHeader('User-Agent') ?? 'unknown';

            // Parse device information
            $deviceInfo = new DeviceInfoService($userAgent);
            $browser = $deviceInfo->getBrowser();
            $os = $deviceInfo->getOS();

            // Initializing GeoLocationService class to obtain the country name based on the IP address
            $geoService = new GeoLocationService();
            $country = $geoService->getCountryNameFromIP($ipAddress);

            // Prepare current recovery context
            $currentContext = [
                'username' => $username,
                'ip_address' => $ipAddress,
                'country' => $country,
                'browser' => $browser,
                'operating_system' => $os,
                'recovery_time' => date('Y-m-d H:i:s'),
            ];

            // Perform risk assessment
            $riskLevel = $this->riskAssessmentService->assessRisk($currentContext);

            return $riskLevel;

        } catch (\Throwable $e) {
            error_log("PasswordRecoveryController: Failed to handle recovery - {$e->getMessage()}");
            return 'Error';
        }
    }


}