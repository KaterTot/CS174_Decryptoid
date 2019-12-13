<?php
	require_once'credentials.php';
	$conn = new mysqli($hn, $un, $pw, $db);
	if($conn->connect_error) die ("Cannot connect to the database.");

	// HTML for user, email, and pw input
	echo <<<_END
			<form method="post" action="createUser.php" enctype="multipart/form-data"><pre>
			User Creation
			Email    <input type="text" name="email">
			Username <input type="text" name="name"> 
			Password <input type="password" name="pass"> 
			<input type="submit" value="Create Account">
			</pre> </form>
_END;
	
	// Checking to see if there are any fields
	if (isset($_POST['email']) && isset($_POST['name']) && isset($_POST['pass']))
	{
		$email = mysql_entities_fix_string($conn, $_POST['email']);
		$uname = mysql_entities_fix_string($conn, $_POST['name']);
		$pword = mysql_entities_fix_string($conn, $_POST['pass']);

		if (preg_match('/[\'^£$%&*()}{@#~?><>,|=+¬]/', $uname)) die("Username can only contain letters, digits and underscores or dashes.");
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)) die ("Please enter a valid email.");
		$salt1 = randomSalt();
		$salt2 = randomSalt();
		$encryptedPword = hash('ripemd128', '$salt1$pword$salt2');

		$query = "INSERT INTO user (username, email, password, salt, salt2) VALUES ('$uname', '$email', '$encryptedPword', '$salt1', '$salt2')";
		echo $query;
		$result = $conn->query($query);
		if(!$result) die("Query failed. Cannot add user to the database. It may already exist. <br><br>");
		
		#$result->close();	//result is a boolean here
		
		//Redirect to login upon successful user creation
		header("Location: login.php");
		exit();
	}
	else
	{
		echo "<br>You must not leave fields blank.<br>";
	}

	function randomSalt()
	{
		$salt = "";
		$saltLength = 10;
		$alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\'^£$%&*@#~?><>,|=+¬]/";

		for ($i = 0; $i < $saltLength; $i++)
		{
			$random = rand(0, strlen($alphabet));
			$salt .= $alphabet[$random-1];
		}

		return $salt;
	}

	// Sanitization functions
	function mysql_entities_fix_string($connection, $string)
	{
		return htmlentities(mysql_fix_string($connection, $string));
	}
	function mysql_fix_string($connection, $string)
	{
		if(get_magic_quotes_gpc()) $string = stripslashes($string);
		return $connection->real_escape_string($string);
	}
?>
