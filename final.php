<?php
	session_start();
	if (isset($_SESSION['username'])) {
	$output = 'Your translated text will go here.';

	require_once'credentials.php';
	$conn = new mysqli($hn, $un, $pw, $db);
	if($conn->connect_error) die ("Cannot connect to the database.");

	// LOGOUT Button to redirect to first page
	echo <<<_END
		<html><head><title>Decryptoid</title></head>
		<form method='post' action='logout.php' enctype='multipart/form-data'>
			<button type="submit">LOGOUT</button>
		</form>
_END;
	// Change this craaaap to JS
	// Form
	echo <<<_END
		<body><form method='post' action='final.php' enctype='multipart/form-data'>
			<!-- Text Input -->
			<textarea name="cipher" style="width:600px; height:200px;">Enter your text here or submit a text file below.</textarea><br>
			<!-- Upload only TXT files -->
			Select TXT File: <input type='file' name='filename' size='10'>
			<!-- Decrypt / encrypt button and select Cipher from drop down list -->
			<select name="cipher" value="Select a Cipher">
				<option value="cipherSel">---Select Cipher---</option>
				<option value="simpleSub">Simple Substitution</option>
				<option value="doubleTrans">Double Transposition</option>
				<option value="rc4">RC4</option>
				<option value="des">DES</option>
			</select><br><br>
			Input your key: <input type="text" name="key">
			<button type="submit" name="btnEncrypt">Encrypt</button>
			<button type="submit" name="btnDecrypt">Decrypt</button>
		</form>
_END;

	// Text output
	echo <<<_END
		<textarea name="output" style="width:600px; height:200px;" readonly='readonly'>$output</textarea>
_END;

	// Text variable
	$text = '';
	// Checking if a file was uploaded
	if($_FILES)
	{
		$name = $_FILES['filename']['name'];
		$name = strtolower(preg_replace("[^A-Za-z0-9]", "", $name));
		if($_FILES['filename']['type'] == 'text/plain')
		{
			echo "Uploaded text file: '$name'<br>";

			$fh = fopen($name, 'r') or die("<br>Failed to open file<br>");
			$text = mysql_entities_fix_string($conn, fgets($fh));
				
			fclose($fh);
		}
		else
		{
			echo "<br>You can only upload txt files.<br>";
		}
	}
	else if(isset($_POST['cipher']))
	{
		$text = mysql_entities_fix_string($conn, $_POST['cipher']);
	}
	else
	{
		echo "<br>You must either enter a text or submit a txt file.<br>";
	}
	echo "</body></html>";

	// Checking which button was pressed
	$action = '';
	$key = '';
	$cipher = '';

	if(isset($_POST['btnEncrypt'])) $action = $encrypt;
	else if(isset($_POST['btnDecrypt'])) $action = 'decrypt';

	// Checking for key
	if (!isset($_POST['key'])) echo "<br>You must enter a key.<br>";
	else $key = mysql_entities_fix_string($conn, $_POST['key']);

	// Checking which cipher was selected
	if (isset($_POST['cipher'])) $cipher = mysql_entities_fix_string($conn, $_POST['cipher']);
	
	if($cipher !== 'cipherSel')
	{
		if($cipher === 'simpleSub') $output = simpleSub($text, $key, $action);
		else if($cipher === 'doubleTrans') $output = doubleTrans($text, $key, $action);
		else if($cipher === 'rc4') $output = rc4($text, $key, $action);
		else if($cipher === 'des') $output = des($text, $key, $action);
	}
	else echo "<br>You must select a cipher.<br>";


	// Inserting into database
	// session aint up, this line wont work
	//$query = "INSERT INTO cipherbank (uID, input, cipher, output, cKey) VALUES ('$_SESSION['uID']','$text', '$cipher', '$output', '$key')";
	$result = $conn->query($query);
	if(!$result) die("Query failed. Cannot add the cipher to the database.<br><br>");

	// Printing a table of all inputs from user
	// session aint up, this line wont work
	//$query = "SELECT * FROM cipherbank WHERE uID = '$_SESSION['uID']'";
	$result = $conn->query($query);
	if(!$result) die ("Query failed. Cannot connect to database.");
	$rows = $result->num_rows;
	echo <<<_END
		<pre><table style="width:50%">
		<tr>
			<th>Input Time</th>
			<th>Cipher</th>
			<th>Key</th>
			<th>Input</th>
			<th>Output</th>
		</tr>
_END;
	for($i = 0; $i < $rows; $i++)
	{
		$result->data_seek($i);
		$row = $result->fetch_array(MYSQLI_NUM);
		$result->close();

		echo <<<_END
		<tr>
			<td style="text-align:center">$row[1]</td>
			<td style="text-align:center">$row[3]</td>
			<td style="text-align:center">$row[2]</td>
			<td style="text-align:center">$row[4]</td>
			<td style="text-align:center">$row[5]</td>
		</tr>
_END;
		echo "</table></pre>";

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
	//$conn->close();


	function simpleSub($text, $key, $action)
	{
		if ($key > 26 || $key < 1)
		{
			return "key must be 26 letters or less";
		}

		$letters = 'abcdefghijklmnopqrstuvwxyz';
		$hold = $letters;

		// removes duplicate characters
		$k = remDup($key);
		for ($i = 0; $i < strlen($k); $i++)
		{
			// if current index of key is in hold
			if (strpos($hold, $k[$i]) !== false)
			{
				$hold = str_replace($k[$i], '', $hold);
			}
		}
		$k .= $hold;

		$cipher = '';
		$text = strtolower($text);

		for ($i = 0; $i < strlen($text); $i++)
		{
			if ($text[$i] === " ") $cipher .= " ";
			else
			{
				if ($action === "Encrypt")
				{
					$index = strpos($letters, $text[$i]);
					$cipher .= $k[$index];
				}
				else if ($action === "Decrypt")
				{
					$index = strpos($k, $text[$i]);
					$cipher .= $letters[$index];
				}
			}
		}

		return $cipher;
	}

	function transp($text, $key, $action)
	{
		if ($key > 26 || $key < 1)
		{
			return "key must be 26 letters or less";
		}

		$letters = 'abcdefghijklmnopqrstuvwxyz';
		$text = strtolower($text);
		$text = str_replace(' ', '', $text);

		// Making the key matrix
		$k = array();
		for ($i = 0; $i < strlen($key); $i++)
		{
			$index = strpos($letters, $key[$i]);
			$hold = array($index);
			array_push($k, $hold);
		}

		// Adding the text to the matrix
		for ($i = 0; $i < strlen($text); $i++)
		{
			array_push($k[$i % count($k)], $text[$i]);
		}
		$decrypt = $k;

		sort($k);

		$cipher = '';

		if ($action === "Encrypt")
		{
			// Printing out the cipher
			for ($i = 0; $i < count($k); $i++)
			{
				for ($j = 1; $j < count($k[$i]); $j++)
				{
					$cipher.= $k[$i][$j];
				}
			}
		}
		else if ($action === "Decrypt")
		{
			$index = 0;
			for ($i = 1; $i < count($decrypt[$index]); $i++)
			{
				for ($j = 0; $j < count($decrypt); $j++)
				{
					$cipher.= $decrypt[$j][$i];
				}
				$index++;
			}
		}
		return $cipher;
	}

	function doubleTrans($text, $key, $action)
	{
		$text = transp($text, $key, $action);
		return transp($text, $key, $action);
	}

	function RC4($text, $key, $action)
	{

	}

	function DES($text, $key, $action)
	{
		
	}

	function remDup($string)
	{
		$result = '';
	
		for ($i = 0; $i < strlen($string); $i++)
		{
			for ($j = $i + 1; $j < strlen($string); $j++)
			{
				if ($string[$i] === $string[$j]) continue 2;
			}
			$result .= $string[$i];
		}

		return $result;
	}
} else echo "Please <a href='login.php'>click here</a> to log in.";

?>
