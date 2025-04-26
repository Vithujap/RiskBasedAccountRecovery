<?php

namespace OCA\RiskBasedAccountRecovery\Controller;

use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCP\AppFramework\Http\TemplateResponse;

use OCA\RiskBasedAccountRecovery\Service\ChallengeService;
use OCA\RiskBasedAccountRecovery\Service\PasswordRecoveryService;

//This class is a controller class that controlls the challenges and validates them.
class ChallengeController extends Controller {
    private $challengeService;
    private $passwordRecoveryService;
    /**
     * Constructor to inject the ChallengeService.
     */
    public function __construct(
        $appName,
        IRequest $request,
        ChallengeService $challengeService,
        PasswordRecoveryService $passwordRecoveryService
    ) {
        parent::__construct($appName, $request);
        $this->challengeService = $challengeService;
        $this->passwordRecoveryService = $passwordRecoveryService;
    }

    /**
     * @NoCSRFRequired
     * @PublicPage
     * @NoAdminRequired
     *
     * Handle the POST request to validate a challenge. This is the central controller to vallidate challanges.
     * This function currently validates security questions and email OTP. If its successfull, a reset link will be sent
     */
    public function validateChallenge() {
        $username = $this->request->getParam('username');
        $riskLevel = $this->request->getParam('riskLevel');
        $response = $this->request->getParam('response');
        $questionText = $this->request->getParam('question'); 
    
        // Debugging: Log received inputs
        error_log("Validating challenge for user: " . ($username ?: 'NULL'));
        error_log("Received Risk Level: " . ($riskLevel ?: 'NULL'));
        error_log("Received Response: " . json_encode($response));
        error_log("Received Question: " . ($questionText ?: 'NULL'));
    
        try {
            // Ensure all required values are provided
            if (!$username) {
                error_log("Validation failed: Missing username.");
                return new TemplateResponse(
                    'RiskBasedAccountRecovery',
                    'challengeForm',
                    [
                        'error' => 'Missing username. Please try again.',
                        'username' => $username,
                        'riskLevel' => $riskLevel ?? Constants::LOW_RISK,
                    ],
                    'guest'
                );
            }
    
            if (!$response && $riskLevel !== Constants::LOW_RISK) {
                error_log("Validation failed: Missing response data.");
                return new TemplateResponse(
                    'RiskBasedAccountRecovery',
                    'challengeForm',
                    [
                        'error' => 'No response data received. Please try again.',
                        'username' => $username,
                        'riskLevel' => $riskLevel ?? Constants::LOW_RISK,
                    ],
                    'guest'
                );
            }

            // Validate security question challenge
            if ($questionText) {
                error_log("Validating Security Question...");
                $isValid = $this->challengeService->validateChallenge($riskLevel, $username, $response, $questionText);
            } else { //Else validate email OTP
                error_log("Validating Email OTP...");
                $isValid = $this->challengeService->validateChallenge($riskLevel, $username, $response);
            }
            //If valid send password reset link. Else throw error
            if ($isValid) {
                $this->passwordRecoveryService->sendResetPasswordLink($username);
                return new TemplateResponse(
                    'RiskBasedAccountRecovery',
                    'challengeForm',
                    [
                        'success' => 'Challenge validated successfully. Please reset your password using the link sent to the email address assosiated with your account',
                        'username' => $username,
                        'riskLevel' => $riskLevel,
                    ],
                    'guest'
                );
            } else {
                error_log("Validation failed: Incorrect response for user: $username.");
                return new TemplateResponse('RiskBasedAccountRecovery', 'passwordRecoveryForm', ['error' => "We couldnt verify your input. Please try again."], 'guest');
            }
        } catch (\Throwable $e) {
            error_log("Exception in validateChallenge(): " . $e->getMessage());
            return new TemplateResponse(
                'RiskBasedAccountRecovery',
                'challengeForm',
                [
                    'error' => 'An error occurred while validating the challenge: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'),
                    'username' => $username,
                    'riskLevel' => $riskLevel ?? Constants::LOW_RISK,
                ],
                'guest'
            );
        }
    }
    
}