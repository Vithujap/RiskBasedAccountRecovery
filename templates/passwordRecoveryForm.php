<html>
<head>
    <title>Password Recovery</title>
    <?php \OCP\Util::addStyle('core', 'guest'); ?>
    <?php \OCP\Util::addStyle('core', 'icons'); ?>
</head>
<body class="guest">
    <div class="wrapper">
        <div class="v-align">
            <header role="banner">
                <div id="header">
                </div>
            </header>

            <div class="guest-box login-box">
                <h2>Password Recovery</h2>
                <p>Please enter your email address or username:</p>

                <?php if (isset($success)): ?>
                    <div class="msg success" style="color:rgb(30, 255, 0); margin-top: 1em;">
                        <p><strong>Success</strong><br><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                <?php elseif (isset($error)): ?>
                    <div class="msg warning" style="color: #ff4d4d; margin-top: 1em;">
                        <p><strong>Error:<br><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></strong></p>
                    </div>
                <?php endif; ?>

                <form action="/index.php/apps/RiskBasedAccountRecovery/password-recovery/form" method="POST">
                    <input type="text" name="email_or_username" placeholder="Email or Username" required />
                    <br><button type="submit" class="primary">Submit</button>
                </form>

                <p style="margin-top: 1em;">
                    <a href="/index.php/login">← Back to login</a>
                </p>
            </div>
        </div>
    </div>
</body>
</html>