<?php
namespace OCA\RiskBasedAccountRecovery\Service;

use OCP\IDBConnection;

class DatabaseService {

    //Holds the database connection instance
    private $dbConnection;

    /**
     * Constructer for DatabaseService
     * @param IDBConnection $dbConnection is the dependency injection for the database connection,
     */
    public function __construct(IDBConnection $dbConnection) {
        $this->dbConnection = $dbConnection;
    }
    /**
     * This function creates the table "rbaa_contextual_user_information" if it does not already exist.
     */
    public function createTable() {
        // Check if the table already exists in MariaDB
        try {
            //Prepearing and executing
            $tableCheckQuery = $this->dbConnection->prepare("
            SELECT TABLE_NAME 
            FROM information_schema.tables 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'rbaa_contextual_user_information'
            ");
            $tableCheckQuery->execute();
            $result = $tableCheckQuery->fetch();

        // If the table does not exist, create it
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
        }
        catch (\Exception $e) {
            //Logging any unexpected errors that occurs during table creation.
            error_log("DatabaseService: Failed to create table - {$e->getMessage()}");
        }

        
    }
    /**
     * Inserts contextual information about a user that logs in into the "rbaa_contextual_user_information" table.
     * @param string $username is the username of the logged-in user
     * @param string $ipAddress is the IP address of the logged-in user.
     * @param string $country is the country from which the user logged in from.
     * @param string $browser is the browser that the user used to log in with.
     * @param string $operatingSystem is the operating system that the user used to log in with.
     * 
     */
    public function insertContextualInformation($username, $ipAddress, $country, $browser, $operatingSystem) {
        try {
            //Prepearing an SQL query to insert the contextual information into the "rbaa_contextual_user_information" table
            $query = $this->dbConnection->prepare("
            INSERT INTO `rbaa_contextual_user_information` 
            (`username`, `ip_address`, `country`, `browser`, `operating_system`)
            VALUES (:username, :ipAddress, :country, :browser, :operatingSystem)
            ");

            //Bind parameters to ensure reliable and secure data insertion. 
            $query->bindParam(':username', $username);
            $query->bindParam(':ipAddress', $ipAddress);
            $query->bindParam(':country', $country);
            $query->bindParam(':browser', $browser);
            $query->bindParam(':operatingSystem', $operatingSystem);

            //Execute the query to insert the record
            $query->execute();
        }
        catch (\Exception $e) {
            //Logging any unexpected errors that occurs during data insertion.
            error_log("DatabaseService: Failed to insert contextual information - {$e->getMessage()}");
        }

    }
}