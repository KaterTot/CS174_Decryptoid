<?php
	//Global Variables
	$USERNAME_LENGTH = 5;

	require_once'credentials.php';
	$conn = new mysqli($hn, $un, $pw, $db);
	if($conn->connect_error) die ("Cannot connect to the database.");

	// HTML for user, email, and pw input
	echo <<<_END

			<head>
			<!-- Javascript for client-side validation -->
			<script>
			console.log("length: ", $USERNAME_LENGTH);
				function validateAccount(form){
					var errors = validateEmail(form.email.value);
					console.log("passed email: ", errors);
					errors += validateUsername(form.name.value);
					console.log("passed uname: ", errors);
					errors += validatePassword(form.pass.value);
			
					console.log("passed password: ", errors);

					if(errors == "") return true;
					else { alert(errors); return false;}
				}
			
				function validateEmail(field){
					//Check if the field is empty
					var trimmedField = field.trim();
					if(trimmedField == "") return 'No Email was entered.\\n';
			
					//Check that the Email only contains alphanumeric, underscores, hyphens, @, and .
					else if(/[^a-zA-Z0-9@_\-\.]/.test(field))
						return 'Invalid symbol in Email. \\n';
			
					else if(!/\S+@\S+\.\S+/.test(field))
						return 'Please enter a valid Email. \\n';

					//return "" if no errors were found	
					console.log('no errors found');
					return "";
				}

				function validateUsername(field){
					//Check if the field is empty
					var trimmedField = field.trim();
					if(trimmedField == "") return 'No Username was entered.\\n';
					
					//Check if the field meets the minimum length requirement
					else if(field.length < $USERNAME_LENGTH)
						return 'Username must contain more than $USERNAME_LENGTH characters. \\n';

					//Check that the username only contains alphanumeric, underscores and hyphens
					else if(/[^a-zA-Z0-9_-]/.test(field))
						return 'Username can only contain alphanumeric symbols, "_" and "-" \\n';
					
					//return "" if no errors were found	
					return "";
				}

				function validatePassword(field){
					//Check if the field is empty
					var trimmedField = field.trim();
					if(trimmedField == "") return 'No Password was entered.\\n';
			
					//Check that the password contains at least one uppercase, one lowercase and one number 0-9
					else if(!/[a-z]/.test(field) || !/[A-Z]/.test(field) || !/[0-9]/.test(field))
						return 'Password requires: at least one Uppercase Symbol,\\n at least one Lowercase Symbol,\\n at least one numeric symbol (0-9) \\n';
					
					//return "" if no errors were found
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
				margin-top: 10%;
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
			#email{
				height: 30px;
			}
			#usrname{
				height: 30px;
				margin-top: 30px;
			}
			#password{
				height: 30px;
				margin-top: 60px;
			}
			#createButton{
				font-family: Arial Black;
				width: 200px;
				height: 20px;
				left: 50%;
				margin-top: 100px;
				margin-left: -100px;
				position:fixed;
			}
			#createButton:hover{
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
			#errorOutput{
				position: fixed;
				top: 80%;
				left: 45%;
			}
			</style>
			</head>

			<h1>Sign Up</h1>
			<form method="post" enctype="multipart/form-data" onsubmit="return validateAccount(this)"><pre>
			<input type="text" name="email" placeholder="Email" id="email">
			<input type="text" name="name" placeholder="Username" id="usrname"> 
			<input type="password" name="pass" placeholder="Password" id="password"> 
			<input type="submit" value="Create Account" id="createButton">
			</pre> </form>
			<div id="errorOutput"> </div>
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
		$encryptedPword = hash('ripemd128', "$salt1$pword$salt2");

		$query = "INSERT INTO user (username, email, password, salt, salt2) VALUES ('$uname', '$email', '$encryptedPword', '$salt1', '$salt2')";
		$result = $conn->query($query);
		if(!$result) die("Query failed. Cannot add user to the database. It may already exist. <br><br>");
		
		#$result->close();	//result is a boolean here
		
		//Redirect to login upon successful user creation
		header("Location: login.php");
		exit();
	}
	else
	{
		echo '<script>document.getElementById("errorOutput").innerHTML = "<p>You must not leave fields blank.</p>";</script>';
	}

	function randomSalt()
	{
		$salt = "";
		$saltLength = 10;
		$alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

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
