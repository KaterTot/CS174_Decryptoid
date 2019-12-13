<?php
	session_start();
	ini_set('session.use_only_cookies', 1);
	ini_set('session.save_path', getcwd() . '/sessions');
	if (!isset($_SESSION['initiated'])) {
		session_regenerate_id();
		$_SESSION['initiated'] = 1;
	}
	require_once'credentials.php';
	$conn = new mysqli($hn, $un, $pw, $db);
	if($conn->connect_error) die ("Cannot connect to the database.");

	// HTML for user and pw input
	echo <<<_END
			<form method="post" enctype="multipart/form-data"><pre>
			User Login
			Username <input type="text" name="name"> Password <input type="password" name="pass"> <input type="submit" value="LOGIN">
			</pre> </form>
_END;

	// CREATE USER Button to redirect to user creation page
	echo <<<_END
				<form method='post' action='createUser.php' enctype='multipart/form-data'><pre>
					New user?
					<button type="submit">Create Account</button>
				</pre></form>
_END;

	// Checking user and password against db
	if(isset($_POST['name']) && isset($_POST['pass']))
	{
		$uname = mysql_entities_fix_string($conn, $_POST['name']);
		$pword = mysql_entities_fix_string($conn, $_POST['pass']);
		$query = "SELECT * FROM user WHERE username='$uname'";
		$result = $conn->query($query);
		if(!$result) die ("Query failed. Cannot connect to database.");
		$row = $result->fetch_array(MYSQLI_ASSOC);
		$result->close();

		$salt = $row[SALT];
		$salt2 = $row[SALT2];
		$token = hash('ripemd128', "$salt$pword$salt2");
		if ($token == $row[password])
		{
			$_SESSION['username'] = $uname;
			ini_set('session.gc_maxlifetime', 60*60*24);
			$_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
			
			header("Location: final.php");
			exit();
		}
		else echo "Invalid username/password combination";

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
