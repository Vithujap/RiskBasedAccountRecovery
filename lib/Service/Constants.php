<?php
namespace OCA\RiskBasedAccountRecovery\Service;

class Constants {
    //Risk Levels
    public const LOW_RISK = "Low Risk";
    public const MEDIUM_RISK = "Medium Risk";
    public const HIGH_RISK = "High Risk";

    //Challenge Types
    public const EMAIL_OTP = "email_otp";
    public const SECURITY_QUESTION = "security_question";
}