control 'SV-102675' do
  title 'Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.'
  desc 'Cookies can be sent to a client using TLS/SSL to encrypt the cookies, but TLS/SSL is not used by every hosted application since the data being displayed does not require the encryption of the transmission. To safeguard against cookies, especially session cookies, being sent in plaintext, a cookie can be encrypted before transmission. To force a cookie to be encrypted before transmission, the cookie "Secure" property can be set.'
  desc 'check', 'Verify the "mod_session_crypto" module is installed.

If the mod_session_crypto module is not being used, this is a finding.'
  desc 'fix', 'Ensure the "mod_session_crypto" module is installed.

Enable encrypted session cookies.

Example:

Session On
SessionCookieName session path=/
SessionCryptoPassphrase secret'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92587'
  tag rid: 'SV-102675r1_rule'
  tag stig_id: 'AS24-W2-000880'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag fix_id: 'F-98829r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
