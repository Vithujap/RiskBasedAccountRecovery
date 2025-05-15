<?php
namespace OCA\RiskBasedAccountRecovery\Service;

/**
 * DeviceInfoServie class is for extracting infromation from a given user agent string, such as the browser and operating system information. 
 */
class DeviceInfoService {
    //Holds the user agent string used to extract information from.
    private $userAgent;
    /**
     * Constructor for DeviceInfoService
     * @param $userAgent is the user agent string of the given user that we want to extract information from.
     */
    public function __construct($userAgent) {
        $this->userAgent = $userAgent;
    }
    /**
     * Detects browser patterns from the user agent string and returns the browser name depending on the pattern.
     * 
     * @return string The name of the detected browser, or "unknown browser" if it cannot detect the browser.
     */
    public function getBrowser(): string {
        try {
            if (preg_match('/Edg/i', $this->userAgent)) return 'Microsoft Edge'; //Detects Microsoft edge browser
            if (preg_match('/Chrome/i', $this->userAgent) && !preg_match('/Edg/i', $this->userAgent)) return 'Google Chrome'; // Detects Google Chrome browser
            if (preg_match('/Safari/i', $this->userAgent) && !preg_match('/Chrome|Edg/i', $this->userAgent)) return 'Safari'; // Detects safari browser
            if (preg_match('/Firefox/i', $this->userAgent)) return 'Mozilla Firefox'; //Detects Firefox browser
            if (preg_match('/MSIE|Trident/i', $this->userAgent)) return 'Internet Explorer'; // Detects Internet Explorer browser
            if (preg_match('/OPR|Opera/i', $this->userAgent)) return 'Opera'; // Detects Opera browser
            return 'Unknown Browser'; //Returns "unkown browser" as a fallback in case no browser patterns matches.
        } 
        catch (\Throwable $e) {
            //Logging any unexpected errors that occurs during browser detection process
            error_log("DeviceInfoService: Failed to get browser information - {$e->getMessage()}");
        }

    }
    /**
     * Detects Operating System patterns from the user agent string and returns the operating system name depending on the pattern.
     * 
     * @return string The name of the detected operating system, or "Unknown OS" if it cannot detect the OS.
     */
    public function getOS(): string {
        try {
            //Array of the common OS patterns mapped to their corresponding OS names.
            $patterns = [
                'Windows 11' => '/Windows NT 10.0;.*Win64.*11/',
                'Windows 10' => '/Windows NT 10.0/',
                'iOS' => '/iPhone|iPad/',
                'Mac OS' => '/Macintosh|Mac OS X/',
                'Android' => '/Android/',
                'Linux' => '/Linux/',
            ];
            //Check each pattern and return the matching OS name if found.
            foreach ($patterns as $os => $pattern) {
                if (preg_match($pattern, $this->userAgent)) return $os;
            }
            //Returns "Unknown OS" if no OS pattern matches as a fall-back.
            return 'Unknown OS';    
        }
        catch (\Throwable $e) {
            //Logging any unexpected errors that occurs during OS detection process
            error_log("DeviceInfoService: Failed to get OS information - {$e->getMessage()}");
        }
    }
}