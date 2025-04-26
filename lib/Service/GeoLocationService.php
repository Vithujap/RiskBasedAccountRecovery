<?php

namespace OCA\RiskBasedAccountRecovery\Service;

/**
 * This class fetches a country name based on a given IP address by sending a GET request to https://ipinfo.io, retrieving the country code, 
 * and convert it to the full country name using data from a local JSON file. 
 */
class GeoLocationService {
    
    /**
     * Get country code from IP address by doing a GET request to https://ipinfo.io 
     *
     * @param string $ip The IP address to lookup
     * @return string|null The country name or null if not found
     */
    public function getCountryNameFromIP($ip) {
        try {
            // Set up the API URL
            $url = "https://ipinfo.io/{$ip}";

            // Initialize the curl session
            $curl = curl_init($url);
            curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
            
            // Execute curl and fetching the response
            $response = curl_exec($curl);
            
            // Check for errors related to curl
            if (curl_errno($curl)) {
                error_log('cURL error: ' . curl_error($curl), ['app' => 'risk_based_account_recovery']);
                curl_close($curl);
                return null;
            }

            // Close the curl session
            curl_close($curl);

            // Decode JSON response to array
            $data = json_decode($response, true);
            
            // Check if 'country' data is available
            if (isset($data['country'])) {

                // Converting the country code to full name
                return $this->convertCountryCodeToName($data['country']);
            } else {
                error_log('Country data not found in response');
                return null;
            }
        }
        catch (\Throwable $e) {
            //Logging any unexpected errors that occurs during retrieving the country name from IP
            error_log("getCountryNameFromIP: Failed to get country from IP: - {$e->getMessage()}");
        }

    }
    
    /**
     * Convert country code to country name
     *
     * @param string $countryCode Country code (e.g., "NO")
     * @return string Country name (e.g., "Norway") or country code as fallback.
     */
    private function convertCountryCodeToName($countryCode) {
        try {
            //Defining the path to the JSON file containing the country codes and their corresponding country names
            $filepath = __DIR__.'/../Data/country_codes.json';

            //Check if the file exists and is readable
            if (file_exists($filepath) && is_readable($filepath)) {

                //Get the contents of the JSON file
                $jsonContent = file_get_contents($filepath);

                //Decode the JSON file into an array
                $countryNames = json_decode($jsonContent,true);

                //Returning the country name if found, otherwise returns the country code as a fallback
                return $countryNames[$countryCode] ?? $countryCode; 
            }
            else {
                //Logging an error if the JSON file cannot be accessd.
                error_log('Country codes JSON file not found or not readable.');

                //Return the country code as fallback
                return $countryCode;
            }
        }
        catch (\Throwable $e) {
            //Logging any unexpected errors that occurs during convertion of country code to name
            error_log("convertCountryCodeToName: Failed to convert country code to name: - {$e->getMessage()}");
        } 
    }
}