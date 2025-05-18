<?php
// Benign: Sanitized input
$name = htmlspecialchars($_GET['name']);
echo "Hello, $name";

// Malicious: Unsanitized direct output
echo $_GET['search'];

// Benign: Using htmlentities
$comment = htmlentities($_POST['comment']);
echo $comment;

// Malicious: Dynamic JavaScript injection
$user = $_GET['user'];
echo "<script>document.write('Welcome " . $user . "');</script>";
?>
