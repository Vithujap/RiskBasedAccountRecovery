<?php

namespace OCA\RiskBasedAccountRecovery\Service;
use OCA\RiskBasedAccountRecovery\Service\Constants;
use OCP\IDBConnection;
//This 
class RiskAssessmentServiceV2 {
    private $dbConnection;
    //Low and high ceiling values for the threshold.
    private $lowCeiling = 4.0;
    private $highCeiling = 7.0;
    //Weight for different contextual information
    private $ipBaseWeight = 2;
    private $countryBaseWeight = 3;
    private $browserBaseWeight = 1;
    private $osBaseWeight = 2;


    /**
     * Constructor to inject dependencies.
     */
    public function __construct(IDBConnection $dbConnection) {
        $this->dbConnection = $dbConnection;
    }
    /**
     * This function assesses the risk level of the user attempting to recover an account
     * @param array $currentRecovery is an array of the contextual information from the user attempting to recover the account.
     * @return ?string returns the risk level or null.
     */
    public function assessRisk($currentRecovery) : ?string {
        $username = $currentRecovery['username'];
        $query = $this->dbConnection->prepare("
            SELECT * FROM rbaa_contextual_user_information
            WHERE username = :username
            ORDER BY login_time DESC
            LIMIT 50
        ");
        $query->bindParam(':username', $username);
        $query->execute();
        $pastLogins = $query->fetchAll();

        // If there are no past logins, return high risk. Better to treat it as suspicious rather then not suspicious
        if (!$pastLogins) return Constants::HIGH_RISK;

        //Calculate the risk score
        error_log("------------------------");
        error_log("Calculating total risk score for: " . $username);
        $riskScore = $this->calculateContextualRisk($pastLogins, $currentRecovery, true);

        // --- Dynamic Thresholds ---
        $thresholds = $this->getDynamicThresholdsFromUserHistory($pastLogins);

        $riskLevel = match (true) {
            $riskScore >= $thresholds['high'] => Constants::HIGH_RISK,
            $riskScore >= $thresholds['low'] => Constants::MEDIUM_RISK,
            default => Constants::LOW_RISK,
        };

        error_log("Assess Risk from User: {$username} | Risk Score: {$riskScore} | Low Threshold: {$thresholds['low']} | High Threshold: {$thresholds['high']}");

        return $riskLevel;
    }
    /**
     * This function calculates the weighted risk score based on how frequently a value appears in past logins of a user
     * @param array $frequencyMap The map of the historical values like IP, country, browser etc.
     * @param string $value The current value of the recovery attempt to assess
     * @param float $baseWeight The base risk weight assigned to this contextual information.
     * @return float The calculated risk score based on the frequency.
     */
    private function frequencyScore($frequencyMap, $value, $baseWeight) {
        // count represents how many times a specific $value (like IP address, browser, OS etc) has appeared in the past login history.
        $count = $frequencyMap[$value] ?? 0;
        $totalLogins = array_sum($frequencyMap);

        $proportion = $count / $totalLogins;
        if ($proportion === 0) return $baseWeight; 
        // If value was seen in 20% or fewer of past logins, assign 80% of the risk score.
        if ($proportion <= 0.2) return $baseWeight * 0.8; 
        // // If value was seen in 50% or fewer of past logins, assign 60% of the risk score.
        if ($proportion <= 0.5) return $baseWeight * 0.6;
        // if its more than 50% of past logins, assign 0 to the risk score.
        return 0;
    }
    /**
     * This function calculates the standard deviation of an array of numeric values
     * @param array $values Array of the numerical values like timestamps
     * @return float The standard deviation
     */
    private function standardDeviation(array $values): float {
        $count = count($values); //n

        //Need minimum 2 values to perform sample standard deviation. Handle if not.
        if ($count < 2) {
            return 0.0;
        }
        // calculate the avg of the values (x̄)
        $avg = array_sum($values) / $count; 

        // calculate the variance:
        $variance = array_sum(array_map(
            fn($value) => pow($value - $avg, 2), // (x-x̄)^2
             $values
             )) / ($count -1 ); // divide by n - 1

        // return the squared root of the variance, which is the standard deviation (sqrt(variance))
        return sqrt($variance);
    }
    /**
     * This function determines if the current recovery attempt's time is anomaly compared to the average login time from past logins.
     * @param array $pastLogins The array containing the past login records.
     * @param string $currentRecoveryTime The recovery time that is being evaluated.
     * @return float 1 if the time is an anomaly or 0 otherwise.
     */
    private function timeAnomalyScore(array $pastLogins, string $currentRecoveryTime): float {
        // Convert past logins into Unix timestamps format
        $times = array_map(fn($login) => strtotime($login['login_time']), $pastLogins);
        // if there login data is less than 2, it is not enough to reliably detect anomaly. so we class it as not an anomaly
        if (count($times) < 2) return 0;

        // calculate the avg login time
        $avg = array_sum($times)/ count($times);
        // calculate the standard deviation of login times
        $std = $this->standardDeviation($times);

        //if standard deviation is 0, handle this or z score will try to devide by 0 which is not possible.
        if ($std == 0) return 0;

        // convert the current recovery attempt time to a Unix timestamp format
        $recoveryTime = strtotime($currentRecoveryTime);

        //Calculate the Z-score of the recovery time.
        $z = ($recoveryTime - $avg) / $std;
        
        // If the absolute Z-score is more than 1.5, flag as anomaly and return a risk score of 1, else 0.
        return abs($z) > 1.5 ? 1 : 0;
    }

    /**
     * This function calculates a low and high risk score threshold based on the user's historical login behavior.
     * Applies smoothing and capping for established boundaries. 
     * Capped value for low is 4, high is 7.
     * It analyes past login contextual information and compute dynamic risk scoring to define what is considered normal for a user.
     * @param array $pastLogins The array containing the past login records.
     * @return array An array with low and high threshold values.
     */
    private function getDynamicThresholdsFromUserHistory(array $pastLogins): array {
        $scores = [];
        $lowPercentile = 0.6;
        $highPercentile = 0.9;
        //Iterate over each login attempt
        foreach ($pastLogins as $i => $login) {
            // all previous logins are seen as historical data
            $historicalSubset = array_slice($pastLogins, 0, $i);
            // Need atleast 2 past logins to evaluate the threshold normally
            if (count($historicalSubset) < 2) continue;
            // Start calculating a risk score for this login
            $score = $this->calculateContextualRisk($pastLogins, $login, false);
            $scores[] = $score;
        }
        // Sort the scores in ascending order for percentile calculations
        sort($scores);
        $count = count($scores);
        $indexLow = min((int)($count * $lowPercentile), $count -1);
        $indexHigh = min((int)($count * $highPercentile), $count -1);
    
        // Calculate dynamic thresholds based on the sorted historical risk scores.
        // 60th percentiles is the low threshold, 90th percentile becomes the high threshold.
        // Ceiling cap is added to avoid thresholds becoming too loose or tight.
        //Low risk threshold is clamped between 2.5 and 4 (lowCeiling value)
        //High risk threshold is clamped between $low + 2.5 and 7 (highCeiling value)
        $low = max(min($scores[$indexLow], $this->lowCeiling), 2.5);
        $high = max(min($scores[$indexHigh], $this->highCeiling), $low + 2.5);
        return ['low' => round($low, 2), 'high' => round($high, 2)];
    }
    

    /**
     * This function calculates the contextual risk score 
     * @param array $pastLogins is an array of the historical data of past account logins
     * @param array $currentAttempt is an array of the current attempt (either recovery attempt or login) contextual data.
     * @return float the risk score.
     */
    private function calculateContextualRisk(array $pastLogins, array $currentAttempt, bool $logging) : float {
        
        // Frequency maps
        $ipFrequency = array_count_values(array_column($pastLogins, 'ip_address'));
        $countryFrequency = array_count_values(array_column($pastLogins, 'country'));
        $browserFrequency = array_count_values(array_column($pastLogins, 'browser'));
        $osFrequency = array_count_values(array_column($pastLogins, 'operating_system'));

        // Calculates the risk score.
        $score = 0;
        if ($logging) {
        

        error_log("Calculating IP");
        $score += $this->frequencyScore($ipFrequency, $currentAttempt['ip_address'], $this->ipBaseWeight); 
        error_log("Score after IP: " . $score);
        error_log("Calculating Country");
        $score += $this->frequencyScore($countryFrequency, $currentAttempt['country'], $this->countryBaseWeight); 
        error_log("Score after Country: " . $score);
        error_log("Calculating Browser");
        $score += $this->frequencyScore($browserFrequency, $currentAttempt['browser'], $this->browserBaseWeight); 
        error_log("Score after Browser: " . $score);
        error_log("Calculating OS");
        $score += $this->frequencyScore($osFrequency, $currentAttempt['operating_system'], $this->osBaseWeight);
        error_log("Score after OS: " . $score);
        error_log("Calculating time");
        $score += $this->timeAnomalyScore($pastLogins, $currentAttempt['login_time'] ?? $currentAttempt['recovery_time']);
        error_log("Score after time and FINAL risk score: " . $score);
        error_log("------------------------");
        return $score;
        }
        else {
            $score += $this->frequencyScore($ipFrequency, $currentAttempt['ip_address'], $this->ipBaseWeight); 

            $score += $this->frequencyScore($countryFrequency, $currentAttempt['country'], $this->countryBaseWeight); 
 
            $score += $this->frequencyScore($browserFrequency, $currentAttempt['browser'], $this->browserBaseWeight); 

            $score += $this->frequencyScore($osFrequency, $currentAttempt['operating_system'], $this->osBaseWeight);

            $score += $this->timeAnomalyScore($pastLogins, $currentAttempt['login_time'] ?? $currentAttempt['recovery_time']);
            return $score;
        }

    }
    

    
}