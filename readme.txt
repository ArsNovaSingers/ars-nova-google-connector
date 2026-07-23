=== Ars Nova Google Connector ===
Version: 1.0.0

A shared, provider-agnostic cloud connector for Ars Nova WordPress plugins. v1 ships a
Google adapter (Sheets / Docs / Drive). Other plugins call it — they never touch auth.

WHY IT EXISTS
- One place owns the Google identity + auth. Any Ars Nova plugin (Site Notes today,
  anything later) reads/writes Google Sheets, Docs, and Drive by calling simple helpers.
- Built provider-agnostic: every call funnels through ansg_request() (the "Google
  adapter"). Adding another cloud later (Microsoft Graph, Dropbox, AWS...) means adding a
  sibling adapter with its own auth — consumers don't change.

AUTH MODEL (recommended: plain service account)
- Default = a PLAIN service account (no user impersonation). You simply SHARE the target
  Google Sheets / Drive folders with the service-account email (Editor). Lowest risk:
  access is limited to exactly what you share, and it survives staff changes.
  This follows Google's own guidance: prefer a plain service account over domain-wide
  delegation whenever the task can be done by sharing a resource.
- OPTIONAL: user impersonation (domain-wide delegation). Only if a target genuinely
  requires acting as a specific Workspace user (e.g. per-user data you can't share).
  Set "Impersonate user" in settings AND authorize the service account's Client ID for the
  scopes in Google Admin → Security → API controls → Domain-wide delegation.

SETUP
1. Install & activate this plugin.
2. Provide the service-account key ONE of two ways:
   a. RECOMMENDED — define it in wp-config.php (kept out of the database):
        define( 'ANSG_SA_JSON', '{ ...the full service-account JSON on one line... }' );
      (optional) define( 'ANSG_ENC_KEY', 'a-long-random-string' ); // else WP salts are used
   b. Or paste the JSON into Settings → Google Connector. It is stored AES-256 encrypted
      (encryption key derived from your wp-config salts, so the key is not in the DB).
3. Leave "Impersonate user" BLANK for a plain service account.
4. Share the target sheet(s)/Drive folder(s) with the service-account email (Editor).
   For the Website Migration Tracker: share it with the service account, Editor.
5. Settings → Google Connector → "Run test". Green ok:true = working.

SECURITY NOTES
- Preferred key storage order: wp-config constant / server env > encrypted option. Never
  commit the key to a repo; never store it in plaintext.
- The settings page never displays the stored key back.
- Plain service account keeps blast radius tiny: a leak exposes only shared documents.

FOR DEVELOPERS (consuming plugins)
- ansg_sheets_read( $spreadsheetId, 'Tab!A1:D' )                 => array of rows | WP_Error
- ansg_sheets_update( $spreadsheetId, 'Tab!A2:D2', $rows )       => API body | WP_Error
- ansg_sheets_append( $spreadsheetId, 'Tab!A:D', $rows )         => API body | WP_Error
- ansg_sheets_clear( $spreadsheetId, 'Tab!A2:D999' )             => API body | WP_Error
- ansg_sheets_meta( $spreadsheetId )                             => tabs/sheetIds | WP_Error
- ansg_request( $method, $url, [ 'query'=>[], 'body'=>[], 'scopes'=>'...' ] )  // Docs/Drive/anything
  Always check is_wp_error() on the return.

CHANGELOG
- 1.0.0 — Initial release. Google adapter (Sheets/Docs/Drive), plain-SA default with
  optional domain-wide delegation, wp-config-constant or AES-256 encrypted-option key
  storage, admin test button, provider-agnostic core.
