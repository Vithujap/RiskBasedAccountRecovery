<?php

namespace OCA\RiskBasedAccountRecovery\Service;

use OCP\IConfig;
use OCP\IURLGenerator;
use OCP\Security\ISecureRandom;
use OCP\Mail\IMailer;
use OCP\IUserManager;
//This class handles all the Password Recovery service after the challenge has been successfully validated.
class PasswordRecoveryService {
    private $config;
    private $secureRandom;
    private $urlGenerator;
    private $mailer;
    private $userManager;
    /**
     * Constructor to inject dependencies.
     */
    public function __construct(
        IConfig $config,
        ISecureRandom $secureRandom,
        IURLGenerator $urlGenerator,
        IMailer $mailer,
        IUserManager $userManager
    ) {
        $this->config = $config;
        $this->secureRandom = $secureRandom;
        $this->urlGenerator = $urlGenerator;
        $this->mailer = $mailer;
        $this->userManager = $userManager;
    }
    /**
     * This function creates the reset token/resetURL that is important when recovering an account
     * @param string $username The username of the recovery account
     * @return string returns the resetURL that includes the reset token.
     */
    public function createResetToken(string $username): string {
        try {
            $tokenPart1 = $this->secureRandom->generate(64);
            $hexTokenPart1 = bin2hex($tokenPart1);
            $tokenPart2 = hash('sha256', $hexTokenPart1 . $username);
            $tokenPart3 = hash('sha512', $hexTokenPart1 . $tokenPart2 . $username);
            $lostpasswordValue = "$hexTokenPart1|$tokenPart2|$tokenPart3";
    
            $timestamp = time();
            $this->config->setUserValue($username, 'core', 'rbaaLostPassword', $lostpasswordValue);
            $this->config->setUserValue($username, 'core', 'rbaaLostPasswordTimestamp', $timestamp);
    
            $urlToken = rtrim(strtr(base64_encode(hex2bin($hexTokenPart1)), '+/', '-_'), '=');
            return $this->urlGenerator->getAbsoluteURL("/apps/RiskBasedAccountRecovery/password-recovery/updatePassword/$urlToken/$username");
        }
        catch (\Throwable $e) {
            error_log("createResetToken: Failed to create resetToken/URL - {$e->getMessage()}");
            //Returns empty string
            return "";
        }
    }
    /**
     * This function validates the reset token.
     * @param string $urlToken The resetToken from the URL
     * @param string $username The username of the recovery account
     * @return bool returns true or false if the validation was successful or not
     */
    public function validateResetToken(string $urlToken, string $username): bool {
        try {
            $storedValue = $this->config->getUserValue($username, 'core', 'rbaaLostPassword', null);
            $timestamp = $this->config->getUserValue($username, 'core', 'rbaaLostPasswordTimestamp', null);
        
            if ($storedValue === null || $timestamp === null || (time() - (int)$timestamp) > 600) {
                $this->removeResetToken($username);
                error_log("Token validation failed: Missing or expired token for user '$username'.");
                return false;
            }
        
            [$storedToken, $storedHash1, $storedHash2] = explode('|', $storedValue);
            $recreatedUrlToken = rtrim(strtr(base64_encode(hex2bin($storedToken)), '+/', '-_'), '=');
        
            if ($urlToken !== $recreatedUrlToken) {
                error_log("Token validation failed: URL token does not match for user '$username'.");
                return false;
            }
        
            $expectedHash1 = hash('sha256', $storedToken . $username);
            $expectedHash2 = hash('sha512', $storedToken . $storedHash1 . $username);
        
            if ($storedHash1 !== $expectedHash1 || $storedHash2 !== $expectedHash2) {
                error_log("Token validation failed: Hash mismatch for user '$username'.");
                return false;
            }
        
            error_log("Token validation successful for user '$username'.");
            return true;
        }
        catch (\Throwable $e) {
            error_log("validateResetToken: Failed to validate resetToken - {$e->getMessage()}");
            //Returns false
            return false;
        }
    }
    /**
     * This function remvoes the reset token and the timestamp it was created from the DB.
     * @param string $username The username of the recovery account
     */
    public function removeResetToken(string $username): void {
        try {
            $this->config->deleteUserValue($username, 'core', 'rbaaLostPassword');
            $this->config->deleteUserValue($username, 'core', 'rbaaLostPasswordTimestamp');
        }
        catch (\Throwable $e) {
            error_log("removeResetToken: Failed to remove resetToken - {$e->getMessage()}");
        }
    }
    /**
     * This function sends the password reset link to the user's email.
     * @param string $username The username of the recovery account
     */
    public function sendResetPasswordLink(string $username): void {
        try {
            $resetUrl = $this->createResetToken($username);
            $email = $this->config->getUserValue($username, 'settings', 'email', '');
    
            $message = $this->mailer->createMessage();
            $message->setTo([$email => $username])
                ->setSubject('Password Reset Request')
                ->setPlainBody("Click the following link to reset your password: $resetUrl");
            $this->mailer->send($message);
        } catch (\Throwable $e) {
            error_log("sendResetPasswordLink: Failed to send email for user '$username': " . $e->getMessage());
        }
    }
}