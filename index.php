<?php
	ini_set('session.use_only_cookies', 1);
	ini_set('session.save_path', '/home/decryptoid/sessions');
	session_start();

	if (!isset($_SESSION['initiated'])) {
		session_regenerate_id();
		$_SESSION['initiated'] = 1;
	}
	require_once'credentials.php';
	$conn = new mysqli($hn, $un, $pw, $db);
	if($conn->connect_error) die ("Cannot connect to the database.");

	// HTML for user and pw input
	echo <<<_END
			<head>

			<!-- Javascript for client-side validation -->
			<script>
				//Log in validation will only check and notify if there are empty fields
				//since we don't want to give the user too much information about what is
				//incorrect and the server does the real validation.
				function validateLogin(form){
					var errors = validateUsername(form.name.value);
					errors += validatePassword(form.pass.value);
			
					if(errors == "") return true;
					else { alert(errors); return false;}
				}
			
				function validateUsername(field){
					//Check if the field is empty
					var trimmedField = field.trim();
					if(trimmedField == "") return 'No Username was entered.\\n';
			
					//return "" if the user entered something
					return "";
				}

				function validatePassword(field){
					//Check if the field is empty
					var trimmedField = field.trim();
					if(trimmedField == "") return 'No Password was entered.\\n';
					
					//return "" if the user entered something
					return "";
				}
			</script>

			<!-- CSS Styling for the page -->
			<style>
				body{
					font-family: Arial;
					color: white;
					background-color: rgb(38,202,235);
					text-align: center;
					margin-top: 5%;
				}
				input{
					border: none;
					border-radius: 3px;
					margin: 5px;
					width: 300px;
					left: 50%;
					margin-left: -150px;
					position:fixed;
				}
				#usrname{
					height: 30px;
				}
				#password{
					height: 30px;
					margin-top: 30px;
				}
				#loginButton{
					font-family: Arial Black;
					width: 200px;
					height: 20px;
					left: 50%;
					margin-top: 80px;
					margin-left: -100px;
					position:fixed;
				}
				#loginButton:hover{
					background-color: lightgreen;
					color: white;
				}
				#newUser h3{
					font-family: Arial;
					top: 80%;
					left: 50%;
					margin-left: -50px;
					margin-top: -70px;
					position:fixed;
				}
				#newUser button{
					font-family: Arial Black;
					border: none;
					border-radius: 3px;
					margin: 5px;
					width: 300px;
					height: 30px;
					top: 80%;
					left: 50%;
					margin-left: -150px;
					position:fixed;
				}
				#newUser button:hover{
					background-color: lightgreen;
					color: white;
				}
			</style>
			</head>

			<h1>CS174 Decryptoid</h1>
			<h3>User Login</h3>
			<form method="post" enctype="multipart/form-data" onsubmit="return validateLogin(this)"><pre>
			<input type="text" name="name" placeholder="Username" id="usrname"> 
			<input type="password" name="pass" placeholder="Password" id="password"> 
			<input type="submit" value="LOGIN" id="loginButton">
			</pre> </form>
_END;

	// CREATE USER Button to redirect to user creation page
	echo <<<_END
				<form method='post' action='createUser.php' enctype='multipart/form-data' id="newUser"><pre>
					<h3>New user?</h3>
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
		if(!$result) die ("Cannot connect to database.");
		$row = $result->fetch_array(MYSQLI_ASSOC);
		$result->close();

		$salt = $row['SALT'];
		$salt2 = $row['SALT2'];
		$token = hash('ripemd128', "$salt$pword$salt2");

		//If username and password are correct...
		if ($token == $row['password'])
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
