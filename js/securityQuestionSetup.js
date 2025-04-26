document.addEventListener("DOMContentLoaded", function () {
    console.log("Security question script loaded...");

    // Fetch security questions when the user logs in
    fetch('/index.php/apps/RiskBasedAccountRecovery/security-questions/check')
        .then(response => response.json())
        .then(data => {
            console.log("Received data:", data); // Debugging
            if (data.questions && data.questions.length > 0) {
                showSecurityQuestionsPopup(data.questions);
            } else {
                console.log("No security questions found.");
            }
        })
        .catch(error => console.error("Error fetching security question data:", error));

    function showSecurityQuestionsPopup(questions) {
        // Create an overlay
        let overlay = document.createElement("div");
        overlay.id = "securityQuestionsOverlay";
        overlay.style.position = "fixed";
        overlay.style.top = "0";
        overlay.style.left = "0";
        overlay.style.width = "100%";
        overlay.style.height = "100%";
        overlay.style.background = "rgba(0, 0, 0, 0.5)";
        overlay.style.zIndex = "999";

        // Create the popup
        let popup = document.createElement("div");
        popup.id = "securityQuestionsPopup";
        popup.style.position = "fixed";
        popup.style.top = "50%";
        popup.style.left = "50%";
        popup.style.transform = "translate(-50%, -50%)";
        popup.style.background = "#1A43BF"; // Blue background
        popup.style.color = "#FFFFFF"; // White text for contrast
        popup.style.padding = "20px";
        popup.style.borderRadius = "8px";
        popup.style.boxShadow = "0px 4px 6px rgba(0, 0, 0, 0.2)";
        popup.style.zIndex = "1000";
        popup.style.textAlign = "center";
        popup.style.width = "400px";

        // Create the form for selecting security questions
        let formHtml = `
            <h2>Set Up Your Security Questions</h2>
            <form id="securityQuestionsForm">
                <p>Select and answer your security questions:</p>
        `;

        for (let i = 1; i <= 3; i++) {
            formHtml += `
                <label for="question${i}">Question ${i}:</label>
                <select id="question${i}" name="question${i}">
            `;

            // Populate security questions
            questions.forEach(q => {
                formHtml += `<option value="${q.id}">${q.question}</option>`;
            });

            formHtml += `</select>
                <input type="text" name="answer${i}" required placeholder="Your answer">
                <br>
            `;
        }

        formHtml += `
                <button type="submit" style="margin-top:10px; padding:5px 15px;">Save</button>
                <button type="button" id="closePopup" style="margin-top:10px; padding:5px 15px; background:red;">Close</button>
            </form>
        `;

        popup.innerHTML = formHtml;
        overlay.appendChild(popup);
        document.body.appendChild(overlay);

        // Handle form submission
        document.getElementById("securityQuestionsForm").addEventListener("submit", function (e) {
            e.preventDefault();

            let formData = new FormData(this);
            fetch('/index.php/apps/RiskBasedAccountRecovery/security-questions/save', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json().catch(() => {
                throw new Error("Invalid JSON response");
            }))
            .then(data => {
                if (data.success) {
                    alert("Security questions saved successfully.");
                    overlay.remove();
                } else {
                    alert("Error: " + (data.error || "Unknown error"));
                }
            })
            .catch(error => console.error("Error saving security questions:", error));
        });

        // Close button functionality
        document.getElementById("closePopup").addEventListener("click", function () {
            overlay.remove();
        });
    }
});
