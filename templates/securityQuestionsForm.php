<!DOCTYPE html>
<html>
<head>
    <title>Security Questions Setup</title>
</head>
<body>
    <h1>Set Up Your Security Questions</h1>

    <?php if (isset($success)): ?>
        <p style="color: green;"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php elseif (isset($error)): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p>
    <?php endif; ?>

    <form action="/index.php/apps/RiskBasedAccountRecovery/security-questions/save" method="POST">
        <p>Select and answer your security questions:</p>

        <?php for ($i = 1; $i <= 3; $i++): ?>
            <label for="question<?php echo $i; ?>">Question <?php echo $i; ?>:</label>
            <select id="question<?php echo $i; ?>" name="question<?php echo $i; ?>">
                <?php foreach ($questions as $question): ?>
                    <option value="<?php echo htmlspecialchars($question['question'], ENT_QUOTES, 'UTF-8'); ?>">
                        <?php echo htmlspecialchars($question['question'], ENT_QUOTES, 'UTF-8'); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <input type="text" name="answer<?php echo $i; ?>" required>
            <br>
        <?php endfor; ?>

        <button type="submit">Save Security Questions</button>
    </form>
</body>
</html>