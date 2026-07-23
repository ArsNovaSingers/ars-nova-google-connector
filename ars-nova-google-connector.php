<?php
/**
 * Plugin Name: Ars Nova Google Connector
 * Description: Shared, provider-agnostic cloud connector for Ars Nova WordPress plugins. v1 ships a Google adapter (Sheets/Docs/Drive) that any other plugin uses via ansg_sheets_read/append/update() or the generic ansg_request(). Google auth = OAuth 2.0 JWT-bearer with a PLAIN service account by default (share the target files with the SA email); optional user impersonation (domain-wide delegation) if a target genuinely needs it. Secret key is read from the ANSG_SA_JSON wp-config constant first, else from an AES-256 encrypted option (key derived from wp-config salts, never stored in the DB).
 * Version: 1.0.0
 * Author: Ars Nova (Jonathan Raabe) + Claude
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'ANSG_VERSION', '1.0.0' );
define( 'ANSG_OPT', 'ansg_settings' );
define( 'ANSG_DEFAULT_SCOPES', 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/documents https://www.googleapis.com/auth/drive' );

/*
 * ── Provider architecture (why this is structured this way) ────────────────
 * Every Google call funnels through ansg_request(), which is the "Google
 * adapter": it acquires a token (ansg_get_access_token) and issues the HTTP
 * request. To add another cloud later (e.g. Microsoft Graph, Dropbox), add a
 * sibling adapter with its own token strategy — DON'T bolt provider logic onto
 * consumers. Google here uses a plain service account (recommended); other
 * providers would typically use OAuth 2.0 auth-code + refresh token, which is
 * the cross-provider common denominator. Consumers only ever call the high-
 * level helpers, so their code is unaffected by which auth a provider uses.
 * ────────────────────────────────────────────────────────────────────────── */

/** Stored settings (sa_json_enc holds CIPHERTEXT, never plaintext). */
function ansg_settings() {
	$s = get_option( ANSG_OPT, array() );
	if ( ! is_array( $s ) ) { $s = array(); }
	return wp_parse_args( $s, array(
		'sa_json_enc'       => '',
		'impersonate_email' => '', // '' = plain service account (recommended). Set only for domain-wide delegation.
		'scopes'            => ANSG_DEFAULT_SCOPES,
	) );
}

/* -------------------------------------------------------------------------
 * Secret handling — constant first, else AES-256-CTR encrypted option.
 * Encryption key/salt come from wp-config (constants or WP salts), so the key
 * lives OUTSIDE the database that stores the ciphertext.
 * ---------------------------------------------------------------------- */
function ansg_enc_key() {
	if ( defined( 'ANSG_ENC_KEY' ) && '' !== ANSG_ENC_KEY )         { return ANSG_ENC_KEY; }
	if ( defined( 'LOGGED_IN_KEY' ) && '' !== LOGGED_IN_KEY )       { return LOGGED_IN_KEY; }
	if ( defined( 'AUTH_KEY' ) && '' !== AUTH_KEY )                 { return AUTH_KEY; }
	return 'ansg-insecure-fallback-key';
}
function ansg_enc_salt() {
	if ( defined( 'ANSG_ENC_SALT' ) && '' !== ANSG_ENC_SALT )       { return ANSG_ENC_SALT; }
	if ( defined( 'LOGGED_IN_SALT' ) && '' !== LOGGED_IN_SALT )     { return LOGGED_IN_SALT; }
	if ( defined( 'AUTH_SALT' ) && '' !== AUTH_SALT )               { return AUTH_SALT; }
	return 'ansg-insecure-fallback-salt';
}
function ansg_encrypt( $plain ) {
	$plain = (string) $plain;
	if ( '' === $plain || ! function_exists( 'openssl_encrypt' ) ) { return ''; }
	$method = 'aes-256-ctr';
	$iv     = openssl_random_pseudo_bytes( openssl_cipher_iv_length( $method ) );
	$key    = hash( 'sha256', ansg_enc_key(), true );
	$cipher = openssl_encrypt( $plain . ansg_enc_salt(), $method, $key, OPENSSL_RAW_DATA, $iv );
	if ( false === $cipher ) { return ''; }
	return 'ansgv1:' . base64_encode( $iv . $cipher );
}
function ansg_decrypt( $stored ) {
	$stored = (string) $stored;
	if ( '' === $stored ) { return ''; }
	if ( 0 !== strpos( $stored, 'ansgv1:' ) ) { return $stored; } // tolerate legacy plaintext
	$data   = base64_decode( substr( $stored, 7 ) );
	$method = 'aes-256-ctr';
	$ivlen  = openssl_cipher_iv_length( $method );
	$iv     = substr( $data, 0, $ivlen );
	$cipher = substr( $data, $ivlen );
	$key    = hash( 'sha256', ansg_enc_key(), true );
	$plain  = openssl_decrypt( $cipher, $method, $key, OPENSSL_RAW_DATA, $iv );
	if ( false === $plain ) { return ''; }
	$salt = ansg_enc_salt();
	if ( strlen( $plain ) >= strlen( $salt ) && substr( $plain, -strlen( $salt ) ) === $salt ) {
		$plain = substr( $plain, 0, -strlen( $salt ) );
	}
	return $plain;
}

/** Where the key comes from: 'constant' | 'option' | 'none'. */
function ansg_key_source() {
	if ( defined( 'ANSG_SA_JSON' ) && '' !== trim( (string) ANSG_SA_JSON ) ) { return 'constant'; }
	$s = ansg_settings();
	return '' !== trim( (string) $s['sa_json_enc'] ) ? 'option' : 'none';
}

/** Raw decrypted service-account JSON (constant wins), or ''. */
function ansg_get_sa_json() {
	if ( defined( 'ANSG_SA_JSON' ) && '' !== trim( (string) ANSG_SA_JSON ) ) { return (string) ANSG_SA_JSON; }
	$s = ansg_settings();
	return ansg_decrypt( $s['sa_json_enc'] );
}

/** Parsed service-account array, or WP_Error. */
function ansg_sa() {
	$json = ansg_get_sa_json();
	if ( '' === trim( $json ) ) {
		return new WP_Error( 'ansg_no_key', 'No service-account key. Paste it in Settings → Google Connector, or define ANSG_SA_JSON in wp-config.php.' );
	}
	$sa = json_decode( $json, true );
	if ( ! is_array( $sa ) || empty( $sa['client_email'] ) || empty( $sa['private_key'] ) ) {
		return new WP_Error( 'ansg_bad_key', 'Service-account JSON is invalid or missing client_email / private_key.' );
	}
	return $sa;
}

/* -------------------------------------------------------------------------
 * Admin settings page (Settings → Google Connector)
 * ---------------------------------------------------------------------- */
add_action( 'admin_menu', function () {
	add_options_page( 'Ars Nova Google Connector', 'Google Connector', 'manage_options', 'ansg', 'ansg_render_settings' );
} );

add_action( 'admin_init', function () {
	register_setting( 'ansg_group', ANSG_OPT, 'ansg_sanitize_settings' );
} );

function ansg_sanitize_settings( $in ) {
	$out = ansg_settings();
	if ( isset( $in['impersonate_email'] ) ) {
		$out['impersonate_email'] = '' === trim( $in['impersonate_email'] ) ? '' : sanitize_email( $in['impersonate_email'] );
	}
	if ( isset( $in['scopes'] ) && '' !== trim( $in['scopes'] ) ) {
		$out['scopes'] = trim( (string) $in['scopes'] );
	}
	// Only replace the stored key when a new one is pasted; otherwise keep it. Store ENCRYPTED.
	if ( isset( $in['sa_json_new'] ) && '' !== trim( $in['sa_json_new'] ) ) {
		$out['sa_json_enc'] = ansg_encrypt( trim( (string) $in['sa_json_new'] ) );
	}
	ansg_flush_token_cache();
	return $out;
}

function ansg_render_settings() {
	$s      = ansg_settings();
	$source = ansg_key_source();
	$sa     = ansg_sa();
	$sa_email = is_wp_error( $sa ) ? '' : $sa['client_email'];
	$mode   = '' === $s['impersonate_email'] ? 'Plain service account (recommended)' : ( 'Impersonating ' . $s['impersonate_email'] . ' (domain-wide delegation)' );
	?>
	<div class="wrap">
		<h1>Ars Nova Google Connector</h1>
		<p>Shared Google identity for Ars Nova plugins. Other plugins call <code>ansg_sheets_*()</code> / <code>ansg_request()</code> and never handle auth. <strong>Mode:</strong> <?php echo esc_html( $mode ); ?>.</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">Key status</th>
				<td>
					<?php if ( 'constant' === $source ) : ?>
						<span style="color:#00866e;">Loaded from <code>ANSG_SA_JSON</code> in wp-config.php</span>
					<?php elseif ( 'option' === $source ) : ?>
						<span style="color:#00866e;">Stored (encrypted) in this site</span>
					<?php else : ?>
						<span style="color:#b32d2e;">No key set</span>
					<?php endif; ?>
					<?php if ( $sa_email ) : ?> — service account <code><?php echo esc_html( $sa_email ); ?></code><?php endif; ?>
					<?php if ( is_wp_error( $sa ) && 'none' !== $source ) : ?> — <span style="color:#b32d2e;"><?php echo esc_html( $sa->get_error_message() ); ?></span><?php endif; ?>
				</td>
			</tr>
		</table>

		<form method="post" action="options.php">
			<?php settings_fields( 'ansg_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="ansg_email">Impersonate user (optional)</label></th>
					<td>
						<input name="<?php echo esc_attr( ANSG_OPT ); ?>[impersonate_email]" id="ansg_email" type="email" class="regular-text" value="<?php echo esc_attr( $s['impersonate_email'] ); ?>" placeholder="leave blank = plain service account" />
						<p class="description"><strong>Leave blank</strong> for a plain service account (recommended: just share the target Sheets/Drive with the service-account email). Only set this if a target genuinely needs the connector to act as a specific Workspace user — which also requires domain-wide delegation to be authorized for the service account's Client ID in Admin console.</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="ansg_scopes">Scopes</label></th>
					<td>
						<input name="<?php echo esc_attr( ANSG_OPT ); ?>[scopes]" id="ansg_scopes" type="text" class="large-text" value="<?php echo esc_attr( $s['scopes'] ); ?>" />
						<p class="description">Space-separated Google API scopes.</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="ansg_sa">Service-account JSON</label></th>
					<td>
						<textarea name="<?php echo esc_attr( ANSG_OPT ); ?>[sa_json_new]" id="ansg_sa" rows="7" class="large-text code" autocomplete="off" placeholder="<?php echo 'none' === $source ? 'Paste the full service-account key JSON here' : 'A key is already set. Paste new JSON only to replace it.'; ?>"></textarea>
						<p class="description">Stored AES-256 encrypted (key derived from your wp-config salts). The value is never shown back here. Best practice: instead of pasting, define <code>ANSG_SA_JSON</code> in <code>wp-config.php</code>.</p>
					</td>
				</tr>
			</table>
			<?php submit_button( 'Save settings' ); ?>
		</form>

		<hr />
		<h2>Test connection</h2>
		<p>Mints a token and reads a cell from the Website Migration Tracker to verify the whole chain.</p>
		<button class="button button-secondary" id="ansg-test">Run test</button>
		<pre id="ansg-test-out" style="background:#fff;border:1px solid #c3c4c7;padding:10px;max-width:820px;overflow:auto;"></pre>
		<script>
		( function () {
			var btn = document.getElementById( 'ansg-test' ), out = document.getElementById( 'ansg-test-out' );
			btn.addEventListener( 'click', function () {
				out.textContent = 'Testing…';
				fetch( '<?php echo esc_url_raw( rest_url( 'ansg/v1/test' ) ); ?>', {
					headers: { 'X-WP-Nonce': '<?php echo esc_js( wp_create_nonce( 'wp_rest' ) ); ?>' },
					credentials: 'same-origin'
				} ).then( function ( r ) { return r.json(); } )
				  .then( function ( d ) { out.textContent = JSON.stringify( d, null, 2 ); } )
				  .catch( function ( e ) { out.textContent = 'Error: ' + e; } );
			} );
		} )();
		</script>
	</div>
	<?php
}

/* -------------------------------------------------------------------------
 * Google adapter — OAuth 2.0 JWT-bearer token (plain SA, or delegated if set)
 * ---------------------------------------------------------------------- */
function ansg_b64url( $data ) {
	return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
}

function ansg_flush_token_cache() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_ansg\_tok\_%' OR option_name LIKE '\_transient\_timeout\_ansg\_tok\_%'" );
}

/** Access token for the given scopes. Impersonates a user only if one is configured. */
function ansg_get_access_token( $scopes = null ) {
	$s  = ansg_settings();
	$sa = ansg_sa();
	if ( is_wp_error( $sa ) ) { return $sa; }

	$scope = $scopes ? $scopes : $s['scopes'];
	$sub   = trim( (string) $s['impersonate_email'] );
	$key   = 'ansg_tok_' . md5( $scope . '|' . $sub . '|' . $sa['client_email'] );

	$cached = get_transient( $key );
	if ( $cached ) { return $cached; }

	$now      = time();
	$tokenUri = ! empty( $sa['token_uri'] ) ? $sa['token_uri'] : 'https://oauth2.googleapis.com/token';
	$header   = array( 'alg' => 'RS256', 'typ' => 'JWT' );
	$claim    = array(
		'iss'   => $sa['client_email'],
		'scope' => $scope,
		'aud'   => $tokenUri,
		'iat'   => $now,
		'exp'   => $now + 3600,
	);
	if ( '' !== $sub ) { $claim['sub'] = $sub; } // domain-wide delegation only when a user is set

	$signing_input = ansg_b64url( wp_json_encode( $header ) ) . '.' . ansg_b64url( wp_json_encode( $claim ) );
	$signature     = '';
	if ( ! openssl_sign( $signing_input, $signature, $sa['private_key'], 'sha256WithRSAEncryption' ) ) {
		return new WP_Error( 'ansg_sign_failed', 'Failed to sign the JWT (check the private_key in the service-account JSON).' );
	}
	$jwt = $signing_input . '.' . ansg_b64url( $signature );

	$resp = wp_remote_post( $tokenUri, array(
		'timeout' => 20,
		'body'    => array( 'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion' => $jwt ),
	) );
	if ( is_wp_error( $resp ) ) { return $resp; }
	$code = (int) wp_remote_retrieve_response_code( $resp );
	$body = json_decode( wp_remote_retrieve_body( $resp ), true );
	if ( 200 !== $code || empty( $body['access_token'] ) ) {
		$msg = is_array( $body ) && ! empty( $body['error'] )
			? ( $body['error'] . ( ! empty( $body['error_description'] ) ? ': ' . $body['error_description'] : '' ) )
			: ( 'HTTP ' . $code );
		return new WP_Error( 'ansg_token_failed', 'Google token request failed — ' . $msg, array( 'status' => 502 ) );
	}
	$ttl = max( 60, (int) $body['expires_in'] - 60 );
	set_transient( $key, $body['access_token'], $ttl );
	return $body['access_token'];
}

/* -------------------------------------------------------------------------
 * Generic authenticated request — every Google call goes through here.
 * @return array( 'status' => int, 'body' => mixed ) | WP_Error
 * ---------------------------------------------------------------------- */
function ansg_request( $method, $url, $args = array() ) {
	$token = ansg_get_access_token( isset( $args['scopes'] ) ? $args['scopes'] : null );
	if ( is_wp_error( $token ) ) { return $token; }

	if ( ! empty( $args['query'] ) && is_array( $args['query'] ) ) {
		$url .= ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $args['query'] );
	}
	$headers = array( 'Authorization' => 'Bearer ' . $token );
	if ( ! empty( $args['headers'] ) && is_array( $args['headers'] ) ) { $headers = array_merge( $headers, $args['headers'] ); }

	$req = array( 'method' => strtoupper( $method ), 'timeout' => 25, 'headers' => $headers );
	if ( array_key_exists( 'body', $args ) ) {
		if ( is_array( $args['body'] ) ) {
			$req['headers']['Content-Type'] = 'application/json';
			$req['body']                    = wp_json_encode( $args['body'] );
		} else {
			$req['body'] = $args['body'];
		}
	}

	$resp = wp_remote_request( $url, $req );
	if ( is_wp_error( $resp ) ) { return $resp; }
	$code = (int) wp_remote_retrieve_response_code( $resp );
	$body = json_decode( wp_remote_retrieve_body( $resp ), true );
	if ( $code < 200 || $code >= 300 ) {
		$msg = is_array( $body ) && ! empty( $body['error'] )
			? ( is_array( $body['error'] ) ? ( isset( $body['error']['message'] ) ? $body['error']['message'] : wp_json_encode( $body['error'] ) ) : $body['error'] )
			: ( 'HTTP ' . $code );
		return new WP_Error( 'ansg_api_error', 'Google API error — ' . $msg, array( 'status' => $code, 'body' => $body ) );
	}
	return array( 'status' => $code, 'body' => $body );
}

/* -------------------------------------------------------------------------
 * Sheets helpers (consumers call these). Docs/Drive: use ansg_request() directly.
 * ---------------------------------------------------------------------- */
function ansg_sheets_base( $id ) { return 'https://sheets.googleapis.com/v4/spreadsheets/' . rawurlencode( $id ); }

function ansg_sheets_read( $id, $range_a1 ) {
	$r = ansg_request( 'GET', ansg_sheets_base( $id ) . '/values/' . rawurlencode( $range_a1 ) );
	if ( is_wp_error( $r ) ) { return $r; }
	return isset( $r['body']['values'] ) ? $r['body']['values'] : array();
}
function ansg_sheets_update( $id, $range_a1, $rows, $value_input = 'USER_ENTERED' ) {
	$r = ansg_request( 'PUT', ansg_sheets_base( $id ) . '/values/' . rawurlencode( $range_a1 ),
		array( 'query' => array( 'valueInputOption' => $value_input ), 'body' => array( 'values' => $rows ) ) );
	return is_wp_error( $r ) ? $r : $r['body'];
}
function ansg_sheets_append( $id, $range_a1, $rows, $value_input = 'USER_ENTERED' ) {
	$r = ansg_request( 'POST', ansg_sheets_base( $id ) . '/values/' . rawurlencode( $range_a1 ) . ':append',
		array( 'query' => array( 'valueInputOption' => $value_input, 'insertDataOption' => 'INSERT_ROWS' ), 'body' => array( 'values' => $rows ) ) );
	return is_wp_error( $r ) ? $r : $r['body'];
}
function ansg_sheets_clear( $id, $range_a1 ) {
	$r = ansg_request( 'POST', ansg_sheets_base( $id ) . '/values/' . rawurlencode( $range_a1 ) . ':clear', array( 'body' => array() ) );
	return is_wp_error( $r ) ? $r : $r['body'];
}
function ansg_sheets_meta( $id ) {
	$r = ansg_request( 'GET', ansg_sheets_base( $id ), array( 'query' => array( 'fields' => 'sheets.properties' ) ) );
	return is_wp_error( $r ) ? $r : $r['body'];
}

/* -------------------------------------------------------------------------
 * REST: test + token-check (admin only)
 * ---------------------------------------------------------------------- */
add_action( 'rest_api_init', function () {
	register_rest_route( 'ansg/v1', '/test', array(
		'methods'             => 'GET',
		'callback'            => 'ansg_rest_test',
		'permission_callback' => function () { return current_user_can( 'manage_options' ); },
	) );
} );

function ansg_rest_test() {
	$s   = ansg_settings();
	$sa  = ansg_sa();
	$out = array(
		'plugin'      => 'ars-nova-google-connector',
		'version'     => ANSG_VERSION,
		'key_source'  => ansg_key_source(),
		'mode'        => '' === $s['impersonate_email'] ? 'plain_service_account' : 'delegated',
		'impersonate' => $s['impersonate_email'],
		'sa_email'    => is_wp_error( $sa ) ? null : $sa['client_email'],
	);
	if ( is_wp_error( $sa ) )   { $out['ok'] = false; $out['error'] = $sa->get_error_message(); return $out; }
	$token = ansg_get_access_token();
	if ( is_wp_error( $token ) ) { $out['ok'] = false; $out['error'] = $token->get_error_message(); return $out; }
	$out['token'] = 'acquired';
	$vals = ansg_sheets_read( '1ooD-807jBnxvKJXo7MKou4MlERl36EQE30Qml3tpiKE', 'Site Notes!A1:C2' );
	if ( is_wp_error( $vals ) ) {
		$out['ok'] = false;
		$out['error'] = $vals->get_error_message();
		$out['hint'] = 'If this is a permission error, share the tracker sheet with the service-account email above (Editor).';
		return $out;
	}
	$out['ok'] = true;
	$out['sample'] = $vals;
	return $out;
}
