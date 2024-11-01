<?php
/*
Plugin Name: SSL Domain Checker
Plugin URI:  https://www.grit.online/ssl-checker-plugin/
Description: SSL Domain Checker alerts site admin via email before the SSL certificate or domain expires.
Author:      GRIT Online Inc.
Version:     1.0.1
Author URI:  https://www.grit.online/
License:     GPL2
*/
 
// =================================================
// Allow code only if WordPress is loaded
// =================================================
if ( !defined('ABSPATH') ) {
	header( 'HTTP/1.0 403 Forbidden' );
  exit;
}

// =================================================
// Define Constants
// =================================================
if ( ! defined( 'SSL_CHECKER_PLUGIN_VERSION' ) ) {
	define( 'SSL_CHECKER_PLUGIN_VERSION', '1.0.1' );
}

if ( ! defined( 'SSL_CHECKER_PLUGIN_NAME' ) ) {
	define( 'SSL_CHECKER_PLUGIN_NAME', 'SSL Domain Checker' );
}

// =================================================
// Register Hooks
// =================================================
register_activation_hook( __FILE__, 'gritonl_ssl_checker_activate' );
register_deactivation_hook( __FILE__, 'gritonl_ssl_checker_deactivate' );
register_uninstall_hook(__FILE__, 'gritonl_ssl_checker_uninstall');

// =================================================
// Schedule Cron
// =================================================
add_action( 'gritonl_ssl_checker', 'gritonl_ssl_checker_runcheck' );

// =================================================
// Load admin functions only if user is admin
// =================================================
if ( is_admin() ) {
  require_once( dirname( __FILE__ ) . '/admin/ssl_checker_admin.php' );
}

// =================================================
// The Check process and alerting
// =================================================
function gritonl_ssl_checker_runcheck(){
  $plugin_data = get_plugin_data( __FILE__ );
  $admin_email = get_option( 'admin_email' );
  $date_format = get_option( 'date_format' );
  $time_format = get_option( 'time_format' );
  $https_url_with = site_url( null, 'https' );
  $https_url_without = explode("://",$https_url_with);
  $https_url_without = $https_url_without[1];
  $alerts = array();
  
  ### Define email addresses for potential alert
  $to = get_option( 'gritonl_ssl_checker_emails' );
  $to[] = get_option( 'admin_email' );
  
  ### Initiate email content
  $message = "This email was sent from your website \"".get_option( 'blogname' )."\" by the ".$plugin_data['Name']." plugin.";
  $message.="\n\nSSL certificate:";
  
  ### Get SSL Certificate status
  $orignal_parse = parse_url($https_url_with, PHP_URL_HOST);
  $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
  $read = stream_socket_client("ssl://".$orignal_parse.":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

  ### If response is false, create an alert
  if(!$read){
    $alerts[] = "ERROR: Unable to check SSL certificate validity.";
    update_option( 'gritonl_ssl_checker_ssl_expiry_ts', 0 );
  }
  else {
    $cert = stream_context_get_params($read);
    $certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

    ### Provide SSL Details in email content
    $altnames = str_replace ( "DNS:", "", $certinfo['extensions']['subjectAltName'] );
    $message.="\n- Common Name = ".esc_attr($certinfo['subject']['CN']);
    $message.="\n- Subject Alternative Names = ".esc_attr($altnames);
    $message.="\n- Issuer = ".htmlspecialchars_decode(esc_attr($certinfo['issuer']['CN']), ENT_QUOTES | ENT_HTML401);
      
    ### Check if any of the alternate names match the site URL 
    $altnames=str_replace ( " ", "", $altnames );
    $altnames=explode ( "," , $altnames );
    $valid=0; # Assume no match found
    foreach ($altnames as $k => $v){
      if ($v == $https_url_without ){
        $message.="\n- Certificate is valid for ".esc_attr($v);
        $valid++;      
      }
      if (strpos($v, '*.')  !== false ){
        $an = array_reverse(explode ( "." , $v ));
        $bn = array_reverse(explode ( "." , $https_url_without ));
        $anc=0;
        for ($i=0;$i<count($an)-1;$i++){ if ($an[$i] == $bn[$i]){$anc++;} }
        if ($anc == count($an)-1 ) {
          $message.="\n- Certificate is valid for ".esc_attr($https_url_without);
          $valid++;
        }
      }
    }
      
    ### If no URL match found, create an alert
    if (!$valid){ $alerts[] = "ERROR: Certificate is not valid for ".$https_url_without; }
     
    ### Check SSL Certificate expiry 
    $localtz = get_option( 'timezone_string' );
    $tzdiff = get_option('gmt_offset') * 60 * 60;
    $localts = $certinfo['validTo_time_t'] + $tzdiff;
      
    $days_to_expiry = $localts - time();
    $days_to_expiry = $days_to_expiry / 60 / 60 / 24;
  
    $message.="\n- The certificate expires ".date($date_format.' '.$time_format, $localts )." ".$localtz." (".round($days_to_expiry,0)." days from today)";
  
    update_option( 'gritonl_ssl_checker_ssl_expiry', $days_to_expiry );
    update_option( 'gritonl_ssl_checker_ssl_expiry_ts', $localts );
  
    ### Insert alerts into array
    if ( round ( $days_to_expiry, 0 ) == 60 ){ $alerts[] = "WARNING: The SSL certificate expires in 60 days."; }
    if ( round ( $days_to_expiry, 0 ) == 30 ){ $alerts[] = "WARNING: The SSL certificate expires in 30 days."; }
    if ( round ( $days_to_expiry, 0 ) <= 21 && $days_to_expiry > 0 ){ $alerts[] = "WARNING: The SSL certificate expires soon. Please take action to renew the certificate."; }
    if ( $days_to_expiry <= 0 ) { $alerts[] = "ERROR: The SSL certificate has expired. The site may be inaccessible."; }
  }
  
  ### Add SSL alerts to email body
  foreach ( $alerts as $k => $v ){ $message.="\n- ".$v; }
  
  ##################################
  ### SSL Cert checking complete ###
  ##################################
    
  ### Check domain expiry
  $message.="\n\nDomain registration:";
  $dalerts = array();
  
  ### Identify the TLD, and start with that
  $tld = explode('.',$https_url_without);
  $elements = count($tld);
  $tld = array_reverse($tld);
  
  ### Loop URL elements until expiry is found, or fail to find it
  for ($i=1;$i<=$elements;$i++){
    
    ### Construct the query for the iteration
    $query="";
    for ($j=0;$j<$i;$j++){
      if ($j){$query=$tld[$j].".".$query;}
      else $query=$tld[$j].$query;
    }
    
    ### Make the query
    if ($i == 1){$whois=gritonl_ssl_checker_whois('whois.iana.org',$query);}
      else { $whois=gritonl_ssl_checker_whois($server,$query); }
    
    ### Parse query results
    foreach ($whois as $k => $v){
      if ( strpos(strtolower($v),"hois: ") ){
        $v=str_replace ( " " , "", $v);
        $server=explode(":",$v);
        $server=$server[1];    
      }
      if ( strpos(strtolower($v),"this query returned ") ){
        $results=explode("returned ",$v);
        $results=explode(" ",$results[1]);
        $results=$results[0];        
      }
      if ( strpos(strtolower($v),"xpiry date:") ){
        $expiry = $v ;
      }
    }
    
    ### If we have no results, break the loop and create alert
    if (!$results){
      $dalerts[] = "WARNING: Unable to query whois database for ".$query;
      break;
    }
    
    ### If we got the expiry date, break the loop and move on
    if ($expiry) {
      $expiry=strtolower($expiry);
      $expiry=explode("date: ",$expiry);
      $expiryts=strtotime ( $expiry[1] );
      $expiryts+=$tzdiff;
      break;
    }
  }
  
  $message.="\n- Domain = ".$query;
  
  $days_to_expiry = $expiryts - time();
  $days_to_expiry = $days_to_expiry / 60 / 60 / 24;
  if ($expiryts != 0){
    $message.="\n- The domain expires ".date($date_format.' '.$time_format, $expiryts )." ".$localtz." (".round($days_to_expiry,0)." days from today)";
  }
  
  update_option( 'gritonl_ssl_checker_domain_expiry', $days_to_expiry );
  update_option( 'gritonl_ssl_checker_domain_expiry_ts', $expiryts );
  
  ### Insert potential alerts into array
  if ( round ( $days_to_expiry, 0 ) == 60 && $expiry ){ $dalerts[] = "WARNING: The domain expires in 60 days."; }
  if ( round ( $days_to_expiry, 0 ) == 30 && $expiry ){ $dalerts[] = "WARNING: The domain expires in 30 days."; }
  if ( round ( $days_to_expiry, 0 ) <= 21 && $days_to_expiry > 0 && $expiry ){
    $dalerts[] = "WARNING: The domain expires soon. Please take action to renew the certificate.";
    $dalerts[] = "WARNING: The registrar change must be done 15 days before expiry.";
  }
  if ( $days_to_expiry <= 0 && $expiry ) { $dalerts[] = "ERROR: The domain has expired. The site is most likely inaccessible."; }
  
  ### Add domain alerts to email body
  foreach ( $dalerts as $k => $v ){ $message.="\n- ".$v; }
  
  ### Update options register
  $alerts = array_merge ( $alerts, $dalerts);
  update_option( 'gritonl_ssl_checker_errors', count($alerts)+count($dalerts) );
  update_option( 'gritonl_ssl_checker_alerts', $alerts );
  
  ### Make a note if no issues found
  if ( !count($alerts) ){
    $message.="\n\nNo issues found. All good for now!";
  }
  else {
    $message.="\n\nThere are issues. Please have a look at the details above.";
  }
  
  ### Email body Footer
  $message.="\n\nThis Wordpress Plugin is provided by ".$plugin_data['AuthorURI'];
  
  ### Email sender and subject
  $headers = "From: ".get_option( 'blogname' )." <".get_option( 'admin_email' ).">" . "\r\n";
  $subject = "[".$plugin_data['Name']." Alert] Status for ".get_option( 'blogname' );
   
  ### Send email if there are alerts or debug is enabled
  if ( count($alerts) || get_option( 'gritonl_ssl_checker_debug' ) ){ wp_mail($to, $subject, $message, $headers); }
}

// =================================================
// Whois server query
// =================================================
function gritonl_ssl_checker_whois($server,$domain){
  $fp = fsockopen(sanitize_text_field( $server ), 43);
  fwrite($fp, sanitize_text_field( $domain )."\r\n");
  while (!feof($fp)) { $whois[] = fgets($fp, 128); }
  fclose($fp);
  $whoiss = array();
  foreach ($whois as $k => $v){ $whoiss[sanitize_text_field($k)] = sanitize_text_field($v); }
  return $whoiss; # Return sanitized array
}

// =================================================
// Activate plugin function
// =================================================
function gritonl_ssl_checker_activate(){
  # Add cron hook to cron events list
  if ( ! wp_next_scheduled( 'gritonl_ssl_checker' ) ) {
    wp_schedule_event( time(), 'daily', 'gritonl_ssl_checker' );
  }
  
  # Create custom options
  add_option('gritonl_ssl_checker_errors', 0, '', 'no');
  add_option('gritonl_ssl_checker_debug', 0, '', 'no');
  add_option('gritonl_ssl_checker_emails', array(), '', 'no');
  add_option('gritonl_ssl_checker_ssl_expiry', 0, '', 'no');
  add_option('gritonl_ssl_checker_ssl_expiry_ts', 0, '', 'no');
  add_option('gritonl_ssl_checker_alerts', array(), '', 'no');
  add_option('gritonl_ssl_checker_domain_expiry', 0, '', 'no' );
  add_option('gritonl_ssl_checker_domain_expiry_ts', 0, '', 'no' );
}

// =================================================
// Deactivate plugin function, do not delete options
// =================================================
function gritonl_ssl_checker_deactivate(){
  # Remove cron hook from cron events list
  $timestamp = wp_next_scheduled( 'gritonl_ssl_checker' );
  wp_unschedule_event( $timestamp, 'gritonl_ssl_checker' );
}

// =================================================
// Uninstall plugin and delete options
// =================================================  
function gritonl_ssl_checker_uninstall(){
  # Delete plugin options
  delete_option('gritonl_ssl_checker_errors');
  delete_option('gritonl_ssl_checker_debug');
  delete_option('gritonl_ssl_checker_emails');
  delete_option('gritonl_ssl_checker_ssl_expiry');
  delete_option('gritonl_ssl_checker_ssl_expiry_ts');
  delete_option('gritonl_ssl_checker_alerts');
  delete_option('gritonl_ssl_checker_domain_expiry');
  delete_option('gritonl_ssl_checker_domain_expiry_ts');
}

?>
