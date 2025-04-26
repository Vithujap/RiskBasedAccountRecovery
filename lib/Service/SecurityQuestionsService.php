<?php

namespace OCA\RiskBasedAccountRecovery\Service;

use OCP\IDBConnection;
//This class is used to hold functions related to security questions
class SecurityQuestionsService {
    private $dbConnection;
    /**
     * Constructor to inject dependencies.
     */
    public function __construct(IDBConnection $dbConnection) {
        $this->dbConnection = $dbConnection;
    }
    /**
     * This function retireves the user's security questions
     * @param string $username The username of the user
     * @return array of the security questions. Empty array if none are found.
     */
    public function getUserSecurityQuestions(string $username): array {
        try {
            // Fetch user's selected security question IDs
            $query = $this->dbConnection->prepare("
                SELECT question FROM oc_security_questions
                WHERE username = :username
            ");
            $query->bindParam(':username', $username);
            $query->execute();
            $results = $query->fetchAll();
    
            if (!$results) {
                error_log("No security question IDs found for user '$username'.");
                return [];
            }
    
            // Extract question IDs
            $questionIds = array_column($results, 'question');
    
            if (empty($questionIds)) {
                return [];
            }
    
            // Fetch full question texts
            $placeholders = implode(',', array_fill(0, count($questionIds), '?'));
            $questionQuery = $this->dbConnection->prepare("
                SELECT id, question FROM oc_security_question_bank
                WHERE id IN ($placeholders)
            ");
    
            foreach ($questionIds as $index => $id) {
                $questionQuery->bindValue(($index + 1), $id, \PDO::PARAM_INT);
            }
    
            $questionQuery->execute();
            $questions = $questionQuery->fetchAll();

            //if No matching security questions found in
            if (!$questions) {
                return [];
            }
    
            return $questions;
    
        } catch (\Throwable $e) {
            error_log("getUserSecurityQuestions: Error fetching security questions for user '$username': " . $e->getMessage());
            return [];
        }
    }

    /**
     * This function validates the security question challenge
     */
    public function validateChallenge() {
        $username = $this->request->getParam('username');
        $riskLevel = $this->request->getParam('riskLevel'); 
        $response = $this->request->getParam('response');
        $questionText = $this->request->getParam('question');

        // Log received request data
        error_log("Validating challenge for user: " . ($username ?: 'NULL'));
        error_log("Risk Level: " . ($riskLevel ?: 'NULL'));
        error_log("Received response: " . json_encode($response));
        error_log("Selected question: " . ($questionText ?: 'NULL'));

        // If riskLevel is still empty, set medium risk as default
        if (empty($riskLevel)) {
            error_log("Risk level is empty! Setting default to 'Medium Risk'.");
            $riskLevel = Constants::MEDIUM_RISK;
        }
        try {
            if (!$username || !$response) {
                return new TemplateResponse(
                    'RiskBasedAccountRecovery',
                    'challengeForm',
                    ['error' => 'Missing required information. Please try again.', 'username' => $username],
                    'guest'
                );
            }
            $data = [
                'question' => $questionText,
                'response' => $response
            ];
            // Validate based on challenge type
            $isValid = ($riskLevel === Constants::LOW_RISK && $questionText)
                ? $this->challengeService->validateChallenge($riskLevel, $username, $data)
                : $this->challengeService->validateChallenge($riskLevel, $username, $response);

            if ($isValid) {
                $this->passwordRecoveryService->sendResetPasswordLink($username);
                return new TemplateResponse(
                    'RiskBasedAccountRecovery',
                    'challengeForm',
                    ['success' => 'Challenge validated successfully. Please reset your password using the link sent to the email address assosiated with your account.'],
                    'guest'
                );
            } else {
                return new TemplateResponse(
                    'RiskBasedAccountRecovery',
                    'challengeForm',
                    ['error' => 'Invalid challenge response. Please try again.', 'username' => $username],
                    'guest'
                );
            }
        } catch (\Throwable $e) {
            error_log("Exception in validateChallenge(): " . $e->getMessage());
            return new TemplateResponse(
                'RiskBasedAccountRecovery',
                'challengeForm',
                ['error' => 'An error occurred while validating the challenge.', 'username' => $username],
                'guest'
            );
        }
    }
    /**
     * This function verifies the security question and answers
     * @param string $username The username of the recovery account
     * @param string $questionText The security question they selected
     * @param string $userAnswer The security question answer
     * @return bool true or false if the verification was successful
     */
    public function verifySecurityQuestion(string $username, string $questionText, string $userAnswer): bool {
        try {
            // Fetch the question ID first by joining with oc_security_question_bank
            $query = $this->dbConnection->prepare("
                SELECT q.answer_hash, q.salt 
                FROM oc_security_questions q
                INNER JOIN oc_security_question_bank qb ON q.question = qb.id
                WHERE q.username = :username AND qb.question = :questionText
            ");
            $query->bindParam(':username', $username);
            $query->bindParam(':questionText', $questionText);
            $query->execute();
            $result = $query->fetch();

            // If no matching question is found, log and return false
            if (!$result) {
                return false;
            }

            $storedHash = $result['answer_hash'];
            $storedSalt = $result['salt'];

            // Normalize user's input (trim spaces, convert to lowercase for consistency)
            $normalizedAnswer = trim(mb_strtolower($userAnswer, 'UTF-8'));

            // Verify if the stored hash matches the user's input
            if (password_verify($storedSalt . $normalizedAnswer . strrev($storedSalt), $storedHash)) {
                return true;
            } else { //Verification failed
                return false;
            }

        } catch (\Throwable $e) {
            error_log("Error verifying security question for user '$username': " . $e->getMessage());
            return false;
        }
    }


    
    
    
}