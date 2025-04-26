<?php

return [
    // Public route for the Risk Based Account Recovery app
    'routes' => [
        // Allow GET request to view the show recovery form (the first form to fill out username or email)
        [
            'name' => 'passwordRecovery#showRecoveryForm',
            'url' => '/password-recovery/form',
            'verb' => 'GET', 
        ],
        // Allow POST request to handle the form submission of above.
        [
            'name' => 'passwordRecovery#startRecovery',
            'url' => '/password-recovery/form',
            'verb' => 'POST',  
        ],
        //Allow GET request to display the update password form (the form where the user enters their new password)
        [
            'name' => 'passwordRecovery#showUpdatePasswordForm',
            'url' => '/password-recovery/updatePassword/{urlToken}/{username}',
            'verb' => 'GET', 
        ],
        //Allow POST request to handle the form submission of above GET request
        [
            'name' => 'passwordRecovery#updateUserPassword',
            'url' => '/password-recovery/updatePassword',
            'verb' => 'POST', 
        ],
        //Allow POST request to handle the challenge validation, which happens once the user submits their answer to the challenge.
        [
            'name' => 'challenge#validateChallenge',
            'url' => '/validate-challenge',
            'verb' => 'POST', 
        ],
        //Allow POST request to save the security questions from a user
        [
            'name' => 'securityQuestions#saveSecurityQuestions',
            'url' => '/security-questions/save',
            'verb' => 'POST',
            'requirements' => ['user' => '@self']
        ],
        //Allow GET request to check security questions
        [
            'name' => 'securityQuestions#checkSecurityQuestions',
            'url' => '/security-questions/check',
            'verb' => 'GET'
        ],
    ],
];