<?php
namespace OCA\RiskBasedAccountRecovery\Service;

use OCP\IDBConnection;

class DatabaseService {

    private $dbConnection;
    
    /**
     * Constructor to inject dependencies.
     */
    public function __construct(IDBConnection $dbConnection) {
        $this->dbConnection = $dbConnection;
    }

    /**
     * Create the tables needed for the Risk-Based Account Recovery app if they don't exist.
     */
    public function createTables() {
        $this->createContextualInformationTable();
        $this->createSecurityQuestionsTable();
        $this->createSecurityQuestionBank();
        
    }

    /**
     * Create the rbaa_contextual_user_information table if it does not exist.
     */
    private function createContextualInformationTable() {
        try {
            $tableCheckQuery = $this->dbConnection->prepare("
                SELECT TABLE_NAME 
                FROM information_schema.tables 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'rbaa_contextual_user_information'
            ");
            $tableCheckQuery->execute();
            $result = $tableCheckQuery->fetch();

            if (!$result) {
                $createTableQuery = $this->dbConnection->prepare("
                    CREATE TABLE `rbaa_contextual_user_information` (
                        `id` INT AUTO_INCREMENT PRIMARY KEY,
                        `username` VARCHAR(64) NOT NULL,
                        `ip_address` VARCHAR(45) NOT NULL,
                        `country` VARCHAR(128),
                        `browser` VARCHAR(128),
                        `operating_system` VARCHAR(128),
                        `login_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ");
                $createTableQuery->execute();
            }
        } catch (\Throwable $e) {
            error_log("createContextualInformationTable: Failed to create rbaa_contextual_user_information table - {$e->getMessage()}");
        }
    }

    /**
     * Create the oc_security_questions table if it does not exist.
     */
    private function createSecurityQuestionsTable() {
        try {
            $tableCheckQuery = $this->dbConnection->prepare("
                SELECT TABLE_NAME 
                FROM information_schema.tables 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'oc_security_questions'
            ");
            $tableCheckQuery->execute();
            $result = $tableCheckQuery->fetch();
    
            if (!$result) {
                $createTableQuery = $this->dbConnection->prepare("
                    CREATE TABLE `oc_security_questions` (
                        `id` INT AUTO_INCREMENT PRIMARY KEY,
                        `username` VARCHAR(255) NOT NULL,
                        `question` VARCHAR(255) NOT NULL,
                        `answer_hash` VARCHAR(255) NOT NULL,
                        `salt` VARCHAR(255) NOT NULL,
                        UNIQUE `user_question` (`username`, `question`)
                    ) ENGINE=InnoDB;
                ");
                $createTableQuery->execute();
            }
        } catch (\Throwable $e) {
            error_log("createSecurityQuestionsTable: Failed to create oc_security_questions table - {$e->getMessage()}");
        }
    }
    /**
     * This function creates the oc_security_question_bank table if it does not exist and fill it with premade questions.
     */
    public function createSecurityQuestionBank() {
        try {
            // Check if the table already exists
            $tableCheckQuery = $this->dbConnection->prepare("
                SELECT TABLE_NAME 
                FROM information_schema.tables 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'oc_security_question_bank'
            ");
            $tableCheckQuery->execute();
            $result = $tableCheckQuery->fetch();

            // If the table does not exist, create it
            if (!$result) {
                $createTableQuery = $this->dbConnection->prepare("
                    CREATE TABLE `oc_security_question_bank` (
                        `id` INT AUTO_INCREMENT PRIMARY KEY,
                        `question` VARCHAR(255) NOT NULL UNIQUE
                    )
                ");
                $createTableQuery->execute();

                // Insert predefined security questions
                $insertQuestionsQuery = $this->dbConnection->prepare("
                    INSERT INTO `oc_security_question_bank` (question) VALUES
                    ('What is your mother\'s maiden name?'),
                    ('What was your first pet\'s name?'),
                    ('What city were you born in?'),
                    ('What is your favorite color?'),
                    ('What is your favorite food?'),
                    ('What was your high school name?'),
                    ('What is your favorite book?'),
                    ('What is your favorite movie?'),
                    ('What was your childhood nickname?')
                ");
                $insertQuestionsQuery->execute();
            }
        } catch (\Throwable $e) {
            error_log("createSecurityQuestionBank: Failed to create or populate oc_security_question_bank table - {$e->getMessage()}");
        }
    }
    /**
     * This function fetches all the questions from the oc_security_question_bank
     */
    public function fetchAllSecurityQuestions() {
        try {
            $query = $this->dbConnection->prepare("
                SELECT id, question FROM oc_security_question_bank
            ");
            $query->execute();
            return $query->fetchAll();
        } catch (\Throwable $e) {
            error_log("fetchAllSecurityQuestions: Failed to fetch security questions - {$e->getMessage()}");
            return [];
        }
    }

    /**
     * Insert contextual information into the rbaa_contextual_user_information table.
     * @param string $username The username of the account logging in
     * @param string $ipAddress The IP Address of the account logging in
     * @param string $country The country where the user is logging in from
     * @param string $browser The browser the user is using
     * @param string $operatingSystem The Operating system the user is using
     */
    public function insertContextualInformation($username, $ipAddress, $country, $browser, $operatingSystem) {
        try {
            $query = $this->dbConnection->prepare("
                INSERT INTO `rbaa_contextual_user_information` 
                (`username`, `ip_address`, `country`, `browser`, `operating_system`)
                VALUES (:username, :ipAddress, :country, :browser, :operatingSystem)
            ");
            $query->bindParam(':username', $username);
            $query->bindParam(':ipAddress', $ipAddress);
            $query->bindParam(':country', $country);
            $query->bindParam(':browser', $browser);
            $query->bindParam(':operatingSystem', $operatingSystem);
            $query->execute();
        } catch (\Throwable $e) {
            error_log("insertContextualInformation: Failed to insert contextual information - {$e->getMessage()}");
        }
    }
    /**
     * This function is used to store the security questions and answers from a user. The answers are hashed and stored in database
     * @param string $username The username of the account that is attempted to be recovered.
     * @param array $questions The security questions that the user selected and answered.
     */
    public function storeUserSecurityQuestions($username, array $questions) {
        foreach ($questions as $q) {
            $question = $q['question'];
            $answer = trim(mb_strtolower($q['answer'], 'UTF-8')); // Normalize answer
    
            // Generate a unique salt
            $salt = bin2hex(random_bytes(16));
    
            // Hash the answer with the salt (embedded inside the hash)
            $hashedAnswer = password_hash($salt . $answer . strrev($salt), PASSWORD_BCRYPT);
            
    
            try {
                $query = $this->dbConnection->prepare("
                    INSERT INTO oc_security_questions (username, question, answer_hash, salt)
                    VALUES (:username, :question, :answer_hash, :salt)
                    ON DUPLICATE KEY UPDATE answer_hash = :answer_hash, salt = :salt
                ");
                $query->bindParam(':username', $username);
                $query->bindParam(':question', $question);
                $query->bindParam(':answer_hash', $hashedAnswer);
                $query->bindParam(':salt', $salt);
                $query->execute();
            } catch (\Throwable $e) {
                error_log("storeUserSecurityQuestions: Error saving security question for user '$username': " . $e->getMessage());
            }
        }
    }
    /**
     * This function checks if a user has security questions established
     * @param string $username The username of the account that is checked.
     * @return bool returns true or false if the user has security qustions enabled or not.
     */
    public function hasSecurityQuestions(string $username): bool {
        try {
            $query = $this->dbConnection->prepare("
                SELECT COUNT(*) as count FROM oc_security_questions WHERE username = :username
            ");
            $query->bindParam(':username', $username);
            $query->execute();
            $result = $query->fetch();
            
            return $result['count'] >= 3; // Ensure user has set at least 3 questions
        } catch (\Throwable $e) {
            error_log("hasSecurityQuestions: Error checking security questions: " . $e->getMessage());
            return false;
        }
    }
    /**
     * This function gets the UID/username of the user from a given email address
     * @param string $email The email address that is used to retrieve the UID
     * @return ?string Returns the UID if found. Else null.
     */
    public function getUidByEmail(string $email): ?string {
        try {
            $query = $this->dbConnection->prepare("
                SELECT userid FROM oc_preferences 
                WHERE appid = 'settings' 
                  AND configkey = 'email' 
                  AND configvalue = :email
                LIMIT 1
            ");
            $query->bindParam(':email', $email);
            $query->execute();
            $result = $query->fetch();
    
            return $result['userid'] ?? null;
        } catch (\Throwable $e) {
            error_log("getUidByEmail: Error fetching UID by email: " . $e->getMessage());
            return null;
        }
    }

}