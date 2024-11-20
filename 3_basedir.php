<?php

$basedir = "/var/www/app/invoices/";
$filename = $_GET['filename'];

// only files should be read
readfile($basedir.$filename);

?>