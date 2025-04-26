<?php

namespace OCA\RiskBasedAccountRecovery\Challenge;

//This class generates and renderes the NoChallenge challenge data to the frontend.
class NoChallenge {
    /**
     * Render the no challenge output.
     *
     * @param string $username The username of the account.
     * @param string $email The user's email address.
     * @param string $riskLevel The risk level of the user 
     * @return array Information for the frontend to render.
     */
    public function render(string $username, ?string $email, string $riskLevel): array {
        return [
            'type' => 'no_challenge',
            'message' => 'No challenge is required. You will be redirected shortly.',
            'username' => $username,
            'riskLevel' => $riskLevel,
            'status' => 'success'
        ];
    }
    /**
     * Validate the OTP provided by the user.
     *
     * @param string $username The username of the account.
     * @param  $response The response.
     * @return bool True if valid, false otherwise.
     */
    public function validate(string $username, $response): bool {
        return true;
    }
}
