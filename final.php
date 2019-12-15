<?php
	ini_set('session.use_only_cookies', 1);
	ini_set('session.save_path', getcwd() . '/sessions');
	session_start();
	if (!isset($_SESSION['initiated'])) {
		session_regenerate_id();
		$_SESSION['initiated'] = 1;
	}
	if (isset($_SESSION['username']) &&
		($_SESSION['check'] == hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']))) {
	require_once'credentials.php';

	// START PHP FUNCTIONS ---------------------------------------------------------------------------------------
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
	function simpleSub($text, $key, $action)
	{
		if (strlen($key) > 26 || strlen($key) < 1)
		{
			die("key must be 26 letters or less");
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
	function doubleTrans($text, $key, $action)
	{
		if (strlen($key) < 2)
		{
			die("key must be at least 2 letters");
		}
		$letters = 'abcdefghijklmnopqrstuvwxyz';
		$text = strtolower($text);
		$text = str_replace(' ', '', $text);
		$rows = strlen($text) / strlen($key);
		$count = 0;
		$dCipher = '';

		if ($action === "Encrypt")
		{
			while (strlen($text) % strlen($key) !== 0)
			{
				$text .= 'x';
			}
			for ($i = 0; $i < strlen($key); $i++)
			{
				while ($count < strlen($letters))
				{
					$index = strpos($key, $letters[$count]);
					if (!empty($index) || $index === 0)
					{
						$key[strpos($key, $letters[$count])] = ".";
						break;
					}
					else $count++;
				}
				for ($j = 0; $j < $rows; $j++)
				{
					$dCipher .= $text[$j * strlen($key) + $index];
				}
			}
		}
		else if ($action === "Decrypt")
		{
			$columns = array_fill(0, strlen($key), "");

			for ($i = 0; $i < strlen($key); $i++)
			{
				$columns[$i] = substr($text, $rows * $i, $rows);
			}

			$sorted = array_fill(0, strlen($key), '');
			$index = 0;
			
			while ($index < strlen($key))
			{
				if (!empty(strpos($key, $letters[$count])) || strpos($key, $letters[$count]) === 0)
				{
					$sorted[strpos($key, $letters[$count])] = $columns[$index++];
					$key[strpos($key, $letters[$count])] = ".";
				}
				else $count++;
			}
			for ($i = 0; $i < $rows; $i++)
			{
				for ($j = 0; $j < strlen($key); $j++)
				{
					$dCipher .= $sorted[$j][$i];
				}
			}
		}
		return $dCipher;
	}
	function RC4($text, $key)
	{
		$s = array();
		$codes = '';
		for ($i = 0; $i < 256; $i++)
		{
			$s[$i] = $i;
		}
		$j = 0;
		for ($i = 0; $i < 256; $i++)
		{
			$j = ($j + $s[$i] + ord($key[$i % strlen($key)])) % 256;
			swap($s[$i], $s[$j]);
		}
		$a = 0;
		$b = 0;
		
		for ($i = 0; $i < strlen($text); $i++)
		{
			$a = ($a + 1) % 256;
			$b = ($b + $s[$a]) % 256;
			swap($s[$a], $s[$b]);
			$codes .= $text[$i] ^ chr($s[($s[$a] + $s[$b]) % 256]);
		}
		return $codes;
	}
	function swap($a, $b)
	{
		$aHold = $a;
		$a = $b;
		$b = $aHold;
	}
	function DES($text, $key, $action)
	{
		$shifts = array(1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);

		$lp = array(58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8);
		$rp = array(57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7);
		$pc1 = array(57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36);
		$pd1 = array(63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4);

		$e = array(32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1);
		$p = array(16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25);

		$pc2 = array(14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26,  8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32);

		$s = array('1110','0100','1101','0001','0010','1111','1011','1000','0011','1010','0110','1100','0101','1001','0000','0111','0000','1111','0111','0100','1110','0010','1101','0001','1010','0110','1100','1011','1001','0101','0011','1000','0100','0001','1110','1000','1101','0110','0010','1011','1111','1100','1001','0111','0011','1010','0101','0000','1111','1100','1000','0010','0100','1001','0001','0111','0101','1011','0011','1110','1010','0000','0110','1101','1111','0001','1000','1110','0110','1011','0011','0100','1001','0111','0010','1101','1100','0000','0101','1010','0011','1101','0100','0111','1111','0010','1000','1110','1100','0000','0001','1010','0110','1001','1011','0101','0000','1110','0111','1011','1010','0100','1101','0001','0101','1000','1100','0110','1001','0011','0010','1111','1101','1000','1010','0001','0011','1111','0100','0010','1011','0110','0111','1100','0000','0101','1110','1001','1010','0000','1001','1110','0110','0011','1111','0101','0001','1101','1100','0111','1011','0100','0010','1000','1101','0111','0000','1001','0011','0100','0110','1010','0010','1000','0101','1110','1100','1011','1111','0001','1101','0110','0100','1001','1000','1111','0011','0000','1011','0001','0010','1100','0101','1010','1110','0111','0001','1010','1101','0000','0110','1001','1000','0111','0100','1111','1110','0011','1011','0101','0010','1100','0111','1101','1110','0011','0000','0110','1001','1010','0001','0010','1000','0101','1011','1100','0100','1111','1101','1000','1011','0101','0110','1111','0000','0011','0100','0111','0010','1100','0001','1010','1110','1001','1010','0110','1001','0000','1100','1011','0111','1101','1111','0001','0011','1110','0101','0010','1000','0100','0011','1111','0000','0110','1010','0001','1101','1000','1001','0100','0101','1011','1100','0111','0010','1110','0010','1100','0100','0001','0111','1010','1011','0110','1000','0101','0011','1111','1101','0000','1110','1001','1110','1011','0010','1100','0100','0111','1101','0001','0101','0000','1111','1010','0011','1001','1000','0110','0100','0010','0001','1011','1010','1101','0111','1000','1111','1001','1100','0101','0110','0011','0000','1110','1011','1000','1100','0111','0001','1110','0010','1101','0110','1111','0000','1001','1010','0100','0101','0011','1100','0001','1010','1111','1001','0010','0110','1000','0000','1101','0011','0100','1110','0111','0101','1011','1010','1111','0100','0010','0111','1100','1001','0101','0110','0001','1101','1110','0000','1011','0011','1000','1001','1110','1111','0101','0010','1000','1100','0011','0111','0000','0100','1010','0001','1101','1011','0110','0100','0011','0010','1100','1001','0101','1111','1010','1011','1110','0001','0111','0110','0000','1000','1101','0100','1011','0010','1110','1111','0000','1000','1101','0011','1100','1001','0111','0101','1010','0110','0001','1101','0000','1011','0111','0100','1001','0001','1010','1110','0011','0101','1100','0010','1111','1000','0110','0001','0100','1011','1101','1100','0011','0111','1110','1010','1111','0110','1000','0000','0101','1001','0010','0110','1011','1101','1000','0001','0100','1010','0111','1001','0101','0000','1111','1110','0010','0011','1100','1101','0010','1000','0100','0110','1111','1011','0001','1010','1001','0011','1110','0101','0000','1100','0111','0001','1111','1101','1000','1010','0011','0111','0100','1100','0101','0110','1011','0000','1110','1001','0010','0111','1011','0100','0001','1001','1100','1110','0010','0000','0110','1010','1101','1111','0011','0101','1000','0010','0001','1110','0111','0100','1010','1000','1101','1111','1100','1001','0000','0011','0101','0110','1011');
		
		$sBox = array('0000'=>2,'0001'=>3,'0010'=>4,'0011'=>5,'0100'=>6,'0101'=>7,'0110'=>8,'0111'=>9,'1000'=>10,'1001'=>11,'1010'=>12,'1011'=>13,'1100'=>14,'1101'=>15,'1110'=>16,'1111'=>17);
		$kBox = array('00'=>0,'01'=>1,'10'=>2,'11'=>3);

		$min = array(40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25);

		if ($action === 'Decrypt')
		{
			$text = base64_decode($text);
		}

		//convert to bin
		$textToBin = str2bin($text);
		$keyToBin = str2bin($key);

		//initial permutation
		$concatedText = bin2text($textToBin);
		$concatedKey = bin2text($keyToBin);
		$l = initialPerm($concatedText, $lp);
		$r = initialPerm($concatedText, $rp);
		$c = initialPerm($concatedKey, $pc1);
		$d = initialPerm($concatedKey, $pd1);

		$lc = array();
		$ld = array();
		$cshift = implode("", $c);
		$dshift = implode("", $d);

		for($i = 0; $i < 16; $i++)
		{
			$ds = lshift($dshift, $shifts[$i]);
			$cs = lshift($cshift, $shifts[$i]);

			array_push($ld, $dshift);
			array_push($lc, $cshift);

			$dshift = $ds;
			$cshift = $cs;
		}

		$keyPC2 = array();
		for ($i = 0; $i < 16; $i++)
		{
			$val = implode("", initialPerm($lc[$i].$ld[$i], $pc2));
			array_push($keyPC2, $val);
		}

		$s1Data = array_chunk($s, ceil(count($s)) / 8);

		$concatedL = bin2text($l);
		$concatedR = bin2text($r);

		$lHold = array();
		$res = array();

		for ($i = 0; $i < 16; $i++)
		{
			$initial = implode("", initialPerm($concatedR, $e));
			$xor = "";
			for ($j = 0; $j < strlen($initial); $j++)
			{
				if ($action === 'Encrypt') $xor .= ($initial[$j] == $keyPC2[$i][$j]) ? "0" : "1";
				else $xor .= ($initial[$j] == $keyPC2[15 - $i][$j]) ? "0" : "1";
			}

			$split = splitTxt($xor, 6);
			$barr = array();
			$box = 0;
			while ($box < 8)
			{
				$xHold = $sBox[substr($split[$box], 1, 4)];
				$xHoldIn = array_search(substr($split[$box], 1, 4), array_keys($sBox)) + 2;
				$sB = array_chunk($s1Data[$box], ceil(count($s1Data[$box]) / 4));
				$yHold = array_search(substr($split[$box], 0, 1).substr($split[$box], -1), array_keys($kBox));
				array_push($barr, $sB[$yHold][$xHoldIn - 2]);
				$box++;
			}

			$pBox = implode("", initialPerm(bin2text($barr), $p));

			$rTemp = "";
			for($j = 0; $j < strlen($pBox); $j++)
			{
				$rTemp .= ($concatedL[$j] == $pBox[$j]) ? "0" : "1";;
			}

			array_push($res, $rTemp);

			$concatedR = $rTemp;
			$concatedL = ($i == 0) ? bin2text($r) : $res[$i - 1];
			array_push($lHold, $concatedL);
		}
		$finR = $res[15].$res[14];
		$initP = initialPerm($finR, $min);
		$ciph = array_chunk($initP, ceil(count($initP) / 8));
		$a = array();
		$fin = "";

		for ($i = 0; $i < count($ciph); $i++)
		{
			$fin .= chr(bindec(bin2text($ciph[$i])));
		}

		if ($action === 'Encrypt') return base64_encode($fin);
		else if ($action === 'Decrypt') return str_replace("#", "", $fin);
	}

	function splitTxt($x, $y)
	{
		$arr = array();
		for ($i = 0; $i < strlen($x); $i += $y)
		{
			$arr[]= substr($x, $i, $y);
		}
		return $arr;
	}

	function lshift($ar, $shift)
	{
		$str = substr($ar, $shift).substr($ar, 0, $shift);
		return $str;
	}

	function initialPerm($bin, $index)
	{
		$iniP = array();
		for ($i = 0; $i < count($index); $i++)
		{
			array_push($iniP, $bin[$index[$i] - 1]);
		}
		return $iniP;
	}

	//Convert key string to 64 bit binary
	function str2bin($string)
	{
		$len = strlen($string);
		for($i = 0; $i < (8 - $len); $i++)
		{
			$string .= "#";
		}
		$spl = str_split($string);
		$con = array();
		for ($i = 0; $i < count($spl); $i++)
		{
			$bin = decbin(ord($spl[$i]));
			$x = 8 - strlen($bin);
			$y = "";
			$z = 1;
			while ($z <= $x)
			{
				$y .= "0";
				$z++;
			}
			array_push($con, $y.$bin);
		}
		return $con;
	}

	function bin2text($val)
	{
		$t = '';
		for ($i = 0; $i < count($val); $i++)
		{
			$t .= $val[$i];
		}
		return $t;
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

	// END PHP FUNCTIONS -----------------------------------------------------------------------------------------

	$conn = new mysqli($hn, $un, $pw, $db);
	if($conn->connect_error) die ("Cannot connect to the database.");
	// LOGOUT Button to redirect to first page
	echo <<<_END
		<html><head><title>Decryptoid</title></head>
		<form method='post' action='logout.php' enctype='multipart/form-data'>
			<button type="submit">LOGOUT</button>
		</form>
_END;

	// Form
	echo <<<_END
		<body><form method='post' action='final.php' enctype='multipart/form-data'>
			<!-- Text Input -->
			<textarea name="input" style="width:600px; height:200px;">Enter your text here or submit a text file below.</textarea><br>
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

	// Text variable
	$text = '';
	$output = '';
	// Checking if a file was uploaded
	if(!empty($_FILES['filename']['name']))
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
			die("<br>You can only upload txt files.<br>");
		}
	}
	else if(isset($_POST['input']))
	{
		$text = mysql_entities_fix_string($conn, $_POST['input']);
	}
	else
	{
		die("<br>You must either enter a text or submit a txt file.<br>");
	}
	echo "</body></html>";
	// Checking which button was pressed
	$action = '';
	$key = '';
	$cipher = '';
	if(isset($_POST['btnEncrypt'])) $action = 'Encrypt';
	else if(isset($_POST['btnDecrypt'])) $action = 'Decrypt';
	// Checking for key
	if (!isset($_POST['key'])) echo "<br>You must enter a key.<br>";
	else $key = mysql_entities_fix_string($conn, $_POST['key']);
	// Checking which cipher was selected
	if (isset($_POST['cipher'])) $cipher = mysql_entities_fix_string($conn, $_POST['cipher']);
	
	if($cipher !== 'cipherSel')
	{
		if($cipher === 'simpleSub') $output = simpleSub($text, $key, $action);
		else if($cipher === 'doubleTrans') $output = doubleTrans($text, $key, $action);
		else if($cipher === 'rc4') $output = rc4($text, $key);
		else if($cipher === 'des') $output = des($text, $key, $action);
		echo "Output: ".$output;
	}
	else die("<br>You must select a cipher.<br>");
	// Inserting into database
	$uName = $_SESSION['username'];
	$query = "INSERT INTO cipherbank (username, input, cipher, output, cKey, method) VALUES ('$uName','$text', '$cipher', '$output', '$key', '$action')";
	$result = $conn->query($query);
	if(!$result) die("Query failed. Cannot add the cipher to the database.<br><br>");
	// Printing a table of all inputs from user
	$query = "SELECT * FROM cipherbank WHERE username = '$uName'";
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
			<th>Method</th>
		</tr>
_END;
	for($i = 0; $i < $rows; $i++)
	{
		$result->data_seek($i);
		$row = $result->fetch_array(MYSQLI_NUM);

		echo <<<_END
		<tr>
			<td style="text-align:center">$row[1]</td>
			<td style="text-align:center">$row[3]</td>
			<td style="text-align:center">$row[5]</td>
			<td style="text-align:center">$row[2]</td>
			<td style="text-align:center">$row[4]</td>
			<td style="text-align:center">$row[6]</td>
		</tr>
_END;
	}
	echo "</table></pre>";
	$result->close();
	$conn->close();
	
} else echo "Please <a href='logout.php'>click here</a> to log in.";
?>