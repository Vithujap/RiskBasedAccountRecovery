<?php

namespace OCA\RiskBasedAccountRecovery\Service;

use OCP\IDBConnection;
use OCA\RiskBasedAccountRecovery\Service\Constants;
//This class is used to conduct the risk assessment.
class RiskAssessmentService {
    private $dbConnection;

    /**
     * Constructor to inject dependencies.
     */
    public function __construct(IDBConnection $dbConnection) {
        $this->dbConnection = $dbConnection;
    }
    /**
     * This function assesses the risk level of the user attempting to recover an account
     * @param array $currentRecoveryAttempt is an array of the contextual information from the user attempting to recover the account.
     * @return ?string returns the risk level or null.
     */
    public function assessRisk($currentRecoveryAttempt): ?string {
        try {
            $username = $currentRecoveryAttempt['username'];
            $currentIp = $currentRecoveryAttempt['ip_address'];
            $currentCountry = $currentRecoveryAttempt['country'];
            $currentBrowser = $currentRecoveryAttempt['browser'];
            $currentOS = $currentRecoveryAttempt['operating_system'];

            // Fetch the last N login attempts for the user
            $query = $this->dbConnection->prepare("
                SELECT * FROM rbaa_contextual_user_information
                WHERE username = :username
                ORDER BY login_time DESC
                LIMIT 20
            ");
    
            $query->bindParam(':username', $username);
            $query->execute();
            
            $pastLogins = $query->fetchAll();
    
            //If No past logins found. Defaulting to Low Risk.
            if (!$pastLogins) {
                return "Low Risk";
            }
    
            // --- Weight-Based Scoring ---
            $riskScore = 0;
            $ipMismatchCount = 0;
            $countryMismatchCount = 0;
            $browserMismatchCount = 0;
            $osMismatchCount = 0;
    
            foreach ($pastLogins as $login) {
                if ($login['ip_address'] !== $currentIp) {
                    $ipMismatchCount++;
                    $riskScore += 2; // Weight for IP mismatch
                }
                if ($login['country'] !== $currentCountry) {
                    $countryMismatchCount++;
                    $riskScore += 1.5; // Weight for country mismatch
                }
                if ($login['browser'] !== $currentBrowser) {
                    $browserMismatchCount++;
                    $riskScore += 0.5; // Weight for browser mismatch
                }
                if ($login['operating_system'] !== $currentOS) {
                    $osMismatchCount++;
                    $riskScore += 0.5; // Weight for OS mismatch
                }
            }
    
            // --- Statistical Anomaly Detection ---
            $anomalies = 0;
    
            // 1. Detect unusual IP patterns
            $uniqueIps = array_column($pastLogins, 'ip_address');
            $ipFrequency = array_count_values($uniqueIps);
            if (isset($ipFrequency[$currentIp]) && $ipFrequency[$currentIp] < 2) {
                $anomalies++;
                $riskScore += 2; // Anomalous IP detected
            }
    
            // 2. Detect geolocation anomalies
            $uniqueCountries = array_column($pastLogins, 'country');
            if (!in_array($currentCountry, $uniqueCountries)) {
                $anomalies++;
                $riskScore += 2; // Country anomaly
            }
    
            // 3. Time-based anomaly detection
            $loginTimes = array_map(function ($login) {
                return strtotime($login['login_time']);
            }, $pastLogins);
            $averageTime = array_sum($loginTimes) / count($loginTimes);
            $currentRecoveryAttemptTime = time();
            $timeDeviation = abs($currentRecoveryAttemptTime - $averageTime);
            if ($timeDeviation > 3600 * 12) { // More than 12 hours deviation
                $anomalies++;
                $riskScore += 1; // Reduced weight for time anomaly
            }
            // --- Risk Level Determination ---
            if ($riskScore >= 8 || $anomalies >= 3) {
                $riskLevel = Constants::HIGH_RISK;
            } elseif ($riskScore >= 4 || $anomalies >= 2) {
                $riskLevel = "Medium Risk";
            } else {
                $riskLevel = "Low Risk";
            }
    
            return $riskLevel;
        }
        catch (\Throwable $e) {
            error_log("assessRisk: Failed to send email for user '$username': " . $e->getMessage());
            return null;
        }
    }
}