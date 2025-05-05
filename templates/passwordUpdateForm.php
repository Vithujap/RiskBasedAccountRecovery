<!DOCTYPE html>
<html>
<head>
    <title>Reset Your Password</title>
    <?php \OCP\Util::addStyle('core', 'guest'); ?>
</head>
<body class="guest">
    <div class="wrapper">
        <div class="v-align">
            <header role="banner">
                <div id="header"></div>
            </header>

            <div class="guest-box login-box">
                <h2>Reset Your Password</h2>

                <?php if (isset($success) && $success): ?>
                    <p class="success"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
                <?php endif; ?>

                <?php if (isset($error) && $error): ?>
                    <p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
                <?php endif; ?>
                <?php if ((!isset($success) || !$success) && (!isset($error) || !$error)) : ?>
                    <form action="/index.php/apps/RiskBasedAccountRecovery/password-recovery/updatePassword" method="POST">
                        <input type="hidden" name="urlToken" value="<?php echo htmlspecialchars($urlToken, ENT_QUOTES, 'UTF-8'); ?>"> 
                        <input type="hidden" name="username" value="<?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?>">

                        <label for="password">New Password:</label>
                        <br>
                        <input type="password" id="password" name="password" required />

                        <br><button type="submit" class="primary">Update Password</button>
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
