<?php
    \OCP\Util::addStyle('core', 'guest');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Account Recovery Challenge</title>
</head>
<body class="guest">
<div class="wrapper">
    <div class="v-align">
        <header role="banner">
            <div id="header">

            </div>
        </header>

        <div class="guest-box login-box">

            <h2>Account Recovery Challenge</h2>

            <?php if (isset($success)): ?>
                <p class="success"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php elseif (isset($error)): ?>
                <p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
            <?php endif; ?>

            <?php
                error_log("Rendering challengeForm.php - Risk Level: " . (isset($riskLevel) ? $riskLevel : 'NULL'));
            ?>

            <!-- Email OTP Challenge -->
            <?php if (isset($type) && $type === 'email_otp'): ?>
                <p>An OTP has been sent to your email. Enter it below:</p>
                <form action="/index.php/apps/RiskBasedAccountRecovery/validate-challenge" method="POST">
                    <input type="text" id="otp" name="response" placeholder="Enter OTP" required>
                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="riskLevel" value="<?php echo htmlspecialchars($riskLevel, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="type" value="email_otp">
                    <br>
                    <button type="submit" class="primary">Validate</button>
                </form>

            <!-- No Challenge -->
            <?php elseif (isset($type) && $type === 'no_challenge'): ?>
                <form action="/index.php/apps/RiskBasedAccountRecovery/validate-challenge" method="POST">
                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="riskLevel" value="<?php echo htmlspecialchars($riskLevel, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="response" value="no_challenge_pass">
                    <input type="hidden" name="type" value="no_challenge">

                    <p>No additional challenge is required.</p>
                    <button type="submit" class="primary">Continue</button>
                </form>

            <!-- CAPTCHA Challenge -->
            <?php elseif (isset($type) && $type === 'captcha'): ?>
                <p>Please solve the CAPTCHA:</p>
                <form action="/index.php/apps/RiskBasedAccountRecovery/validate-challenge" method="POST">
                    <img src="<?php echo htmlspecialchars($captchaImage, ENT_QUOTES, 'UTF-8'); ?>" alt="CAPTCHA">
                    <input type="text" name="response" placeholder="Enter CAPTCHA" required>
                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="riskLevel" value="<?php echo htmlspecialchars($riskLevel, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="type" value="captcha">
                    <button type="submit" class="primary">Validate</button>
                </form>

            <!-- Security Question Challenge -->
            <?php elseif (isset($type) && $type === 'security_question' && isset($questions) && count($questions) > 0): ?>
                <p>Answer one of your security questions:</p>
                <form action="/index.php/apps/RiskBasedAccountRecovery/validate-challenge" method="POST">
                    <select name="question">
                        <?php foreach ($questions as $question): ?>
                            <option value="<?php echo htmlspecialchars($question['question'], ENT_QUOTES, 'UTF-8'); ?>">
                                <?php echo htmlspecialchars($question['question'], ENT_QUOTES, 'UTF-8'); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <br>
                    <input type="text" name="response" placeholder="Your answer" required>
                    <input type="hidden" name="username" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="riskLevel" value="<?php echo htmlspecialchars($riskLevel, ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="type" value="security_question">
                    <br>
                    <button type="submit" class="primary">Validate</button>
                </form>
            <?php endif; ?>

            <p style="margin-top: 1em;">
                <a href="/index.php/login">← Back to login</a>
            </p>
        </div>
    </div>
</div>
</body>
</html>
