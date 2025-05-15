<?php

namespace OCA\RiskBasedAccountRecovery\Challenge;

use OCA\RiskBasedAccountRecovery\Service\SecurityQuestionsService;
use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
use OCP\ILogger;

//This class generates and renderes the SecurityQuestion challenge data to the frontend.
class SecurityQuestionChallenge {
    private $securityQuestionsService;
    private $logger;

    /**
     * Constructor to inject dependencies.
     */
    public function __construct(SecurityQuestionsService $securityQuestionsService, ILogger $logger) {
        $this->securityQuestionsService = $securityQuestionsService;
        $this->logger = $logger;
    }

    /**
     * Generate a security question challenge for the user.
     *
     * @param string $username The username of the account.
     * @param string|null $email (Not used for this challenge)
     * @return array Information for the frontend to render.
     */
    public function render(string $username, ?string $email = null, string $riskLevel): array {
        //Retrieving the security questions
        $questions = $this->securityQuestionsService->getUserSecurityQuestions($username);

        //Checking if the questions are empty
        if (empty($questions)) {
            $this->logger->error("No security questions found for user '$username'.");
            return ['error' => 'No security questions are set up for this account.'];
        }

        //Renders the list of security questions to frontend
        return [
            'type' => 'security_question',
            'message' => 'Please answer one of your security questions.',
            'questions' => $questions, // Send the list of questions to the frontend
            'username' => $username,
            'riskLevel' => $riskLevel,
        ];
    }

    /**
     * Validate the security question answer.
     *
     * @param string $username The username of the account.
     * @param array $response Contains 'question' (selected question ID) and 'answer' (user input).
     * @return bool True if valid, false otherwise.
     */
    public function validate(string $username, $challengeData): bool {
        try {
            // Ensure challengeData is an array with the required fields
            if (!is_array($challengeData) || !isset($challengeData['question']) || !isset($challengeData['response'])) {
                error_log("Security question validation failed: Missing question or response for user '$username'.");
                return false;
            }
    
            $questionText = $challengeData['question'];
            $userAnswer = trim(mb_strtolower($challengeData['response'], 'UTF-8'));
    
            // Call the verification function in SecurityQuestionsService
            $isValid = $this->securityQuestionsService->verifySecurityQuestion($username, $questionText, $userAnswer);
            
            //Checking if the answer to the security question is valid or not.
            if ($isValid) {
                error_log("Security question validated successfully for user '$username'");
            } else {
                error_log("Security question validation failed: Incorrect answer.");
            }
    
            return $isValid;
        } catch (\Exception $e) {
            error_log("Error verifying security question for user '$username': " . $e->getMessage());
            return false;
        }
    }
    
}
