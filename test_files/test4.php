<?php
// Benign: Sanitized email display
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
echo "Your email: " . $email;

// Malicious: Inline JS using unsanitized user input
$msg = $_GET['msg'];
echo "<body onload=\"alert('$msg')\">";

// Benign: Outputting a static message
echo "Submission received successfully.";

// Malicious: Dangerous attribute injection
echo "<img src='x' onerror='alert(\"XSS\")'>";
?>
