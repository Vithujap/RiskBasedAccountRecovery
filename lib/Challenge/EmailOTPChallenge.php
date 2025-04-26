<?php

namespace OCA\RiskBasedAccountRecovery\Challenge;

use OCP\IConfig;
use OCP\Mail\IMailer;
use OCP\ILogger;

//This class generates and renderes the EmailOTP challenge data to the frontend.
class EmailOTPChallenge {
    private $config;
    private $mailer;
    private $logger;

    /**
     * Constructor to inject dependencies.
     */
    public function __construct(IConfig $config, IMailer $mailer, ILogger $logger) {
        $this->config = $config;
        $this->mailer = $mailer;
        $this->logger = $logger;
    }

    /**
     * Generate and send an OTP to the user's email.
     *
     * @param string $username The username of the account.
     * @param string $email The user's email address.
     * @return array Information for the frontend to render.
     */
    public function render(string $username, ?string $email, string $riskLevel): array {
        if (!$email) {
            $this->logger->error("No email found for user '$username'.");
            return ['error' => 'Email address not found for this account.'];
        }
    
        // Generate OTP
        $otp = random_int(100000, 999999);
        $salt = bin2hex(random_bytes(16));
        $otpHash = hash('sha256', $otp . $salt);
    
        // Store OTP hash
        $this->config->setUserValue($username, 'core', 'emailOtpData', "$otpHash|$salt");
        $this->config->setUserValue($username, 'core', 'emailOtpTimestamp', time());
    
        // Send OTP email
        try {
            $message = $this->mailer->createMessage();
            $message->setTo([$email => $username])
                    ->setSubject('Your OTP Code')
                    ->setPlainBody("Your OTP is: $otp. It expires in 10 minutes.");
            $this->mailer->send($message);
    
            $this->logger->info("OTP sent to user '$username'.");
    
            return [
                'type' => 'email_otp', // 🛠️ Ensure type is included
                'message' => 'An OTP has been sent to your email. Please enter it below.',
                'username' => $username,
                'riskLevel' => $riskLevel,
            ];
        } catch (\Exception $e) {
            $this->logger->error("Failed to send OTP email: " . $e->getMessage());
            return ['error' => 'Failed to send OTP. Please try again later.'];
        }
    }
    

    /**
     * Validate the OTP provided by the user.
     *
     * @param string $username The username of the account.
     * @param string $inputOtp The OTP provided by the user.
     * @return bool True if valid, false otherwise.
     */
    public function validate(string $username, $inputOtp): bool {
        // Retrieve the stored OTP data and timestamp
        $storedData = $this->config->getUserValue($username, 'core', 'emailOtpData', null);
        $timestamp = $this->config->getUserValue($username, 'core', 'emailOtpTimestamp', null);

        if (!$storedData || !$timestamp) {
            $this->logger->error("Failed OTP validation: Missing data for user '$username'.");
            return false;
        }

        // Check if the OTP has expired (10 minutes validity)
        if (time() - (int)$timestamp > 600) { // 600 seconds = 10 minutes
            $this->logger->warning("OTP expired for user '$username'.");
            $this->invalidate($username); // Invalidate the expired OTP
            return false;
        }

        // Split the stored data into hash and salt
        list($storedHash, $storedSalt) = explode('|', $storedData);

        // Hash the input OTP with the stored salt
        $inputHash = hash('sha256', $inputOtp . $storedSalt);

        // Compare the input hash with the stored hash
        if ($inputHash !== $storedHash) {
            $this->logger->warning("Invalid OTP provided for user '$username'.");
            return false;
        }

        // Log successful validation
        $this->logger->info("OTP validated successfully for user '$username'.");

        // Invalidate the OTP after successful validation
        $this->invalidate($username);

        return true;
    }

    /**
     * Invalidate the OTP for a user. It will delete the OTP data and timestamp from DB.
     *
     * @param string $username The username of the account.
     */
    private function invalidate(string $username) {
        $this->config->deleteUserValue($username, 'core', 'emailOtpData');
        $this->config->deleteUserValue($username, 'core', 'emailOtpTimestamp');
        $this->logger->info("OTP invalidated for user '$username'.");
    }
}