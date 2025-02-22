control 'SV-102673' do
  title 'The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.'
  desc "A cookie is used when a web server needs to share data with the client's browser. The data is often used to remember the client when the client returns to the hosted application at a later date. A session cookie is a special type of cookie used to remember the client during the session. The cookie will contain the session identifier (ID) and may contain authentication data to the hosted application. To protect this data from easily being compromised, the cookie can be encrypted.

When a cookie is sent encrypted via SSL/TLS, an attacker must spend a great deal of time and resources to decrypt the cookie. If, along with encryption, the cookie is compressed, the attacker can now use a combination of plaintext injection and inadvertent information leakage through data compression to reduce the time needed to decrypt the cookie. This attack is called Compression Ratio Info-leak Made Easy (CRIME).

Cookies shared between the web server and the client when encrypted should not also be compressed."
  desc 'check', 'Search the Apache configuration files for the "SSLCompression" directive.

If the directive does not exist, this is a not a finding.

If the directive exists and is not set to "off", this is a finding.'
  desc 'fix', 'Search the Apache configuration files for the "SSLCompression" directive.

If the directive is present, set it to "off".'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91889r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92585'
  tag rid: 'SV-102673r1_rule'
  tag stig_id: 'AS24-W2-000860'
  tag gtitle: 'SRG-APP-000439-WSR-000153'
  tag fix_id: 'F-98827r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
