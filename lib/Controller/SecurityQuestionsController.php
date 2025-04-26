<?php

namespace OCA\RiskBasedAccountRecovery\Controller;

use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCA\RiskBasedAccountRecovery\Service\DatabaseService;
use OCA\RiskBasedAccountRecovery\Service\SecurityQuestionsService;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IUserSession;
use OCP\AppFramework\Http\DataResponse;
//This class is the controller class for the Security question setup process. Many of these functions are called from frontend.
class SecurityQuestionsController extends Controller {
    private $securityQuestionsService;
    private $databaseService;
    private $userSession;

    public function __construct(
        $appName,
        IRequest $request,
        SecurityQuestionsService $securityQuestionsService,
        DatabaseService $databaseService,
        IUserSession $userSession
    ) {
        parent::__construct($appName, $request);
        $this->securityQuestionsService = $securityQuestionsService;
        $this->databaseService = $databaseService;
        $this->userSession = $userSession;
    }

    /**
     *
     * Show the form to set up security questions.
     */
    public function showSetupForm() {
        //Retrieving user session
        $user = $this->userSession->getUser();

        //Handling if user session is not found
        if (!$user) {
            error_log("User session not found. Redirecting to login page.");
            return new TemplateResponse(
                'RiskBasedAccountRecovery',
                'securityQuestionsForm',
                ['error' => 'User session could not be found. Please log in again.'],
                'blank'
            );
        }
        //Getting username
        $username = $user->getUID();

        //Retrieving all security questions from the bank
        $questions = $this->databaseService->fetchAllSecurityQuestions();

        //Display the security question form to the user
        return new TemplateResponse(
            'RiskBasedAccountRecovery',
            'securityQuestionsForm',
            ['questions' => $questions],
            'blank'
        );
    }

/**
 * @NoCSRFRequired
 * @PublicPage
 * @NoAdminRequired
 *
 * Check if the user has set up security questions
 */
public function checkSecurityQuestions() {
    try {
        // Fetch all available security questions from the database
        $questions = $this->databaseService->fetchAllSecurityQuestions();

        //Returning the security questions
        return new DataResponse([
            'questions' => $questions
        ]);
    } catch (\Throwable $e) {
        error_log("Error in checkSecurityQuestions: " . $e->getMessage());
        return new DataResponse(['error' => 'Internal server error'], 500);
    }
}

    /**
     * @NoCSRFRequired
     * @RequireLogin
     * @NoAdminRequired
     *
     * Save the user's selected security questions and answers.
     */
    public function saveSecurityQuestions() {
        try {
            // Retrieve the currently logged-in user's username
            $user = $this->userSession->getUser();
            if (!$user) {
                return new DataResponse(['error' => 'User is not logged in. Please log in and try again.'], 401);
            }
            $username = $user->getUID();
    
            $question1 = $this->request->getParam('question1');
            $answer1 = $this->request->getParam('answer1');
            $question2 = $this->request->getParam('question2');
            $answer2 = $this->request->getParam('answer2');
            $question3 = $this->request->getParam('question3');
            $answer3 = $this->request->getParam('answer3');
    
            // Validate that all fields are filled
            if (!$question1 || !$answer1 || !$question2 || !$answer2 || !$question3 || !$answer3) {
                return new DataResponse(['error' => 'All questions and answers must be filled out.'], 400);
            }
    
            // Validate that each question is unique
            if ($question1 === $question2 || $question1 === $question3 || $question2 === $question3) {
                return new DataResponse(['error' => 'Each security question must be unique. Please try again.'], 400);
            }
    
            // Save the security questions and answers
            $this->databaseService->storeUserSecurityQuestions(
                $username,
                [
                    ['question' => $question1, 'answer' => $answer1],
                    ['question' => $question2, 'answer' => $answer2],
                    ['question' => $question3, 'answer' => $answer3]
                ]
            );
    
            return new DataResponse(['success' => true]);
    
        } catch (\Throwable $e) {
            error_log("Failed to save security questions: " . $e->getMessage());
            return new DataResponse(['error' => 'Internal server error'], 500);
        }
    }
    
}