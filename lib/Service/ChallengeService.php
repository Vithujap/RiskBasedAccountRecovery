<?php
namespace OCA\RiskBasedAccountRecovery\Service;

use OCA\RiskBasedAccountRecovery\Challenge\EmailOTPChallenge;
use OCA\RiskBasedAccountRecovery\Challenge\SecurityQuestionChallenge;
use OCA\RiskBasedAccountRecovery\Challenge\NoChallenge;
use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
use OCA\RiskBasedAccountRecovery\Service\Constants;

use OCP\IDBConnection;
/**
 * This class is the ChallengeService class. It is used to generate and validate the challenges on the frontend part. 
 * This class is used to select what challenges to show the user depending on their risk level.
 * This is connected to the POST/GET requests from the routes.php
 */ 
class ChallengeService {
    private $emailOTPChallenge;
    private $securityQuestionChallenge;
    private $noChallenge;
    private $dbConnection;
    private DatabaseService $databaseService;

    /**
     * Constructor to inject dependencies.
     */
    public function __construct(
        EmailOTPChallenge $emailOTPChallenge,
        SecurityQuestionChallenge $securityQuestionChallenge,
        NoChallenge $noChallenge,
        IDBConnection $dbConnection,


    ) {
        $this->emailOTPChallenge = $emailOTPChallenge;
        $this->securityQuestionChallenge = $securityQuestionChallenge;
        $this->noChallenge = $noChallenge;
        $this->dbConnection = $dbConnection;
        $this->databaseService = new DatabaseService($this->dbConnection);
  
    }
    /**
     * This function is used to define what types of challenges are displayed to the user depending on the risk level.
     * @param string $riskLevel The risk level of the user attempting to recover their account.
     * @param string $username The username of the account that is attempted to be recovered.
     */
    public function getChallenge(string $riskLevel, $username) {
        try {
        switch ($riskLevel) {
            case Constants::LOW_RISK:
                return $this->noChallenge;
            case Constants::MEDIUM_RISK:
                return $this->emailOTPChallenge;
            case Constants::HIGH_RISK:
                //Checking if the user has setup security questions. If no security questions is setup, default to email OTP
                if (!$this->databaseService->hasSecurityQuestions($username)) {
                    return $this->emailOTPChallenge;
                }
                return $this->securityQuestionChallenge;
            default:
                throw new \InvalidArgumentException("Unknown risk level: $riskLevel");
        }
        } catch (\Throwable $e) {
            error_log("getChallenge failed for: '$username'. Error:" . $e->getMessage());
        }
    }
    /**
     * This function is used generate the challenge on the frontend part. 
     * @param string $riskLevel The risk level of the user attempting to recover their account.
     * @param string $username The username of the account that is attempted to be recovered.
     * @param ?string $email The email address of the accouunt unless its null
     * @return array Information for the frontend to render.
     */
    public function generateChallenge(string $riskLevel, string $username, ?string $email = null): array {
        try {
            $challenge = $this->getChallenge($riskLevel, $username);

            // Generate challenge and ensure it includes the type
            $challengeData = $challenge->render($username, $email,$riskLevel);
        
            if (!isset($challengeData['type'])) {
                error_log("ChallengeService: Missing type in challenge response for risk level: $riskLevel");
            }
        
            return $challengeData;
        }
        catch (\Throwable $e) {
            error_log("generateChallenge failed for: '$username'. Error:" . $e->getMessage());
            return new TemplateResponse(
                'RiskBasedAccountRecovery',
                'challengeForm',
                [
                    'error' => 'Failed to render challenge',
                    'username' => $username,
                    'riskLevel' => $riskLevel ?? Constants::LOW_RISK,
                ],
                'guest'
            );
        }
    }
    /**
     * This function is used validate the challenge. This function is called from the frontend once user has answered the challenge.
     * @param string $riskLevel The risk level of the user attempting to recover their account.
     * @param string $username The username of the account that is attempted to be recovered.
     * @param $response The user's input/answer for the challenge
     * @param string $questionText The security question the user answered IF the challenge was security questions
     * @return bool if validation is successful or not
     */
    public function validateChallenge(string $riskLevel, string $username, $response, $questionText = null): bool {
        try {
            $challenge = $this->getChallenge($riskLevel, $username);
    
            // If it's a security question challenge, pass both question & response
            if ($questionText != null) {
                return $challenge->validate($username, ['question' => $questionText, 'response' => $response]);
            }
        
            // Otherwise, validate as usual (e.g., for OTP)
            return $challenge->validate($username, $response);
        }
        catch (\Throwable $e) {
            error_log("validateChallenge failed for: '$username'. Error:" . $e->getMessage());
            return false;
        }
    }
    
}