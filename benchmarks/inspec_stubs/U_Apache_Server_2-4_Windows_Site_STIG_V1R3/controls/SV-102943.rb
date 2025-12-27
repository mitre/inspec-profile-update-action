control 'SV-102943' do
  title 'Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e., HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.'
  desc 'check', 'Verify the "mod_session_crypto" module is installed.

If the mod_session_crypto module is not being used, this is a finding.'
  desc 'fix', 'Ensure the mod_session_crypto module is installed.

Enable encrypted session cookies.

Example:

Session On
SessionCookieName session path=/
SessionCryptoPassphrase secret'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-92161r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92855'
  tag rid: 'SV-102943r1_rule'
  tag stig_id: 'AS24-W2-000870'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-99099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
