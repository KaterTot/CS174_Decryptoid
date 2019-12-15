<?php
	session_start();
	destroy_session_and_data();
	header("Location: index.php");

	//destroys session
	function destroy_session_and_data() {
		$_SESSION = array();
		setcookie(session_name(), '', time() - 2592000, '/');
		session_destroy();
	}
?>
