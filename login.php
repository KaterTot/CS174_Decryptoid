<?php
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
		$result = $conn->query($query);
		if(!$result) die ("Query failed. Cannot connect to database.");
		$row = $result->fetch_array(MYSQLI_NUM);
		$result->close();

		$salt = $row[4];
		$salt2 = $row[5];
		$token = hash('ripemd128', "$salt$pword$salt2");
		if ($token == $row[3])
		{
			header("Location: final.php");
			exit();
		}
		else echo "Invalid username/password combination";

	}

?>