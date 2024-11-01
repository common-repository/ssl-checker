<?php

// =================================================
// Allow code only if plugin is active
// =================================================
if ( ! defined( 'SSL_CHECKER_PLUGIN_VERSION' ) ) {
	header( 'HTTP/1.0 403 Forbidden' );
  exit;
}

// =================================================
// Allow code only for admins
// =================================================
if ( !is_admin() ) {
  wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
}
 
// =================================================
// Register options page in admin menu
// =================================================
add_action( 'admin_menu', 'gritonl_ssl_checker_plugin_menu' );

function gritonl_ssl_checker_plugin_menu() {
	 add_options_page( 'SSL Domain Checker Settings', 'SSL Domain Checker', 'manage_options', 'gritonl_ssl_checker', 'gritonl_ssl_checker_plugin_options' );
}

// =================================================
// If Errors, Activate Admin Panel Error Notice
// =================================================
if ( get_option( 'gritonl_ssl_checker_errors' ) ){
  wp_enqueue_style( 'gritonl_ssl_checker', plugins_url('css/admin.css',__FILE__ ), array(), time(), 'all' );
  add_action( 'admin_notices', 'gritonl_ssl_checker_alert' );
}
else {
  remove_action( 'admin_notices', 'gritonl_ssl_checker_alert' );
}

// Admin panel header alert
function gritonl_ssl_checker_alert() {
	echo '<p id="gritonl_ssl_checker_alert"><a id="gritonl_ssl_checker_alert" href="'.menu_page_url( "gritonl_ssl_checker", false ).'">SSL/Domain Expiry ALERT!</a></p>';
}

// =================================================
// Plugin Admin Menu Options
// =================================================
function gritonl_ssl_checker_plugin_options() {
	if ( !current_user_can( 'manage_options' ) )  {
		wp_die( __( 'You do not have sufficient permissions to access this page.' ) );
	}
  
  if( isset( $_POST['settings-saved'] ) && wp_verify_nonce($_POST['nonce'], 'settings-saved') ){
    update_option( 'gritonl_ssl_checker_debug', sanitize_text_field($_POST['debug']) );  
    $emails = explode (',',$_POST['emails']);
    foreach ($emails as $k => $v){
      $emails[$k] = sanitize_email( $v );
    }
    $emails = array_filter($emails);                        # Remove potential null values
    update_option( 'gritonl_ssl_checker_emails', $emails ); # Insert emails into options
    gritonl_ssl_checker_runcheck(); 
  }
  
	echo '<div class="wrap">';
	echo '<h1>'.SSL_CHECKER_PLUGIN_NAME.' Settings</h1>';
 
  ?>
  <form action="<?php menu_page_url( "gritonl_ssl_checker", true ); ?>" method="post">
    <?php if (get_option( 'gritonl_ssl_checker_debug' )){$checked="checked";} else $checked=""; ?>
    <table class="form-table">
        <tr>
          <th scope="row">SSL Certificate expires on</th>
          <?php if ( get_option('gritonl_ssl_checker_ssl_expiry_ts') != 0 ){ ?>
            <td><?php echo date(get_option( 'date_format' ).' '.get_option( 'time_format' ), get_option( 'gritonl_ssl_checker_ssl_expiry_ts' ) )." ".get_option( 'timezone_string' ) ; ?> (<?php echo round(get_option( 'gritonl_ssl_checker_ssl_expiry' )); ?> days from today)</td>
            <?php } else echo "<td>Unable to check</td>"; ?>
        </tr>
        <tr>
          <th scope="row">Domain registration expires on</th>
          <?php if ( get_option( 'gritonl_ssl_checker_domain_expiry_ts' ) != 0 ){ ?>
            <td><?php echo date(get_option( 'date_format' ).' '.get_option( 'time_format' ), get_option( 'gritonl_ssl_checker_domain_expiry_ts' ) )." ".get_option( 'timezone_string' ) ; ?> (<?php echo round(get_option( 'gritonl_ssl_checker_domain_expiry' )); ?> days from today)</td>
            <?php } else echo "<td>Unable to check</td>"; ?>
        </tr>
        <tr>
          <th scope="row">Admin Email Address</th>
          <td><?php echo get_option( 'admin_email' )?></td>
        </tr>
        <tr>
          <th scope="row">Additional Email Addresses</th>
          <td><input type="text" size="80" name="emails" value="<?php
            $c=0;
            foreach ( get_option( 'gritonl_ssl_checker_emails' ) as $k => $v ) {
              if ( $c ) { echo ", ".$v; }
                else { echo $v; }
              $c++;
            }
            ?>"><p class="description" id="emails-description">Comma separated list of emails to receive alerts</p></td>
        </tr>
        <tr>
          <th scope="row">Debug</th>
          <td><input type="checkbox" name="debug" value=1 <?php echo $checked; ?>>Send email even if there are no errors</td>
        </tr>
    </table>
    <br />
    <input type="hidden" name="nonce" value="<?php echo wp_create_nonce('settings-saved'); ?>">
    <input class="button button-primary" name="settings-saved" type="submit" value="Save Changes & Check">
  </form>
  <?php

  echo '<br />Alerts currently: '.get_option( 'gritonl_ssl_checker_errors' );
  foreach ( get_option( 'gritonl_ssl_checker_alerts' ) as $k => $v ){
    echo '<br>- '.$v;
  }
  
  $localts = wp_next_scheduled( 'gritonl_ssl_checker' ) + get_option('gmt_offset') * 60 * 60;
  echo '<br /><br />Next automatic check: '.date(get_option( 'date_format' ).' '.get_option( 'time_format' ), $localts );
  
  echo '<br /><br />This Wordpress Plugin is provided by <a href="https://www.grit.online/">GRIT Online Inc.</a>';

	echo '</div>';
    
}

?>