document.addEventListener('DOMContentLoaded', function() {

    // Select the "Forgot Password" link by its ID
    const forgotPasswordLink = document.querySelector('#lost-password');

    if (forgotPasswordLink) {
        // Add a click event listener to intercept the click
        forgotPasswordLink.addEventListener('click', function(e) {
            e.preventDefault();  // Prevent the default behavior (i.e., navigating to the default forgot password page)

            console.log("Redirecting to the custom password recovery page...");

            // Redirect to the custom password recovery page
            window.location.href = '/index.php/apps/RiskBasedAccountRecovery/password-recovery/form';  // Modify this URL if needed
        });
    } else {
        console.error("Forgot password link not found!");  // Debugging line
    }
});