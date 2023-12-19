control 'SV-206436' do
  title 'Web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.'
  desc "A cookie is used when a web server needs to share data with the client's browser. The data is often used to remember the client when the client returns to the hosted application at a later date. A session cookie is a special type of cookie used to remember the client during the session. The cookie will contain the session identifier (ID) and may contain authentication data to the hosted application. To protect this data from easily being compromised, the cookie can be encrypted.

When a cookie is sent encrypted via SSL/TLS, an attacker must spend a great deal of time and resources to decrypt the cookie. If, along with encryption, the cookie is compressed, the attacker can now use a combination of plaintext injection and inadvertent information leakage through data compression to reduce the time needed to decrypt the cookie. This attack is called Compression Ratio Info-leak Made Easy (CRIME).

Cookies shared between the web server and the client when encrypted should not also be compressed."
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether cookies are being sent to the client using SSL/TLS.

If the transmission is through a SSL/TLS connection, but the cookie is not being compressed, this finding is NA.

If the web server is using SSL/TLS for cookie transmission and the cookie is also being compressed, this is a finding.'
  desc 'fix', 'Configure the web server to send the cookie to the client via SSL/TLS without using cookie compression.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6697r377900_chk'
  tag severity: 'medium'
  tag gid: 'V-206436'
  tag rid: 'SV-206436r879810_rule'
  tag stig_id: 'SRG-APP-000439-WSR-000153'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-6697r377901_fix'
  tag 'documentable'
  tag legacy: ['SV-70259', 'V-56005']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
