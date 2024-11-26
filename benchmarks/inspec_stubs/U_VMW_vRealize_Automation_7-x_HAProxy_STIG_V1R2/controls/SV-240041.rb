control 'SV-240041' do
  title 'HAProxy must be configured with FIPS 140-2 compliant ciphers for https connections.'
  desc 'Transport Layer Security (TLS) is optional for a public web server. However, if authentication is being performed, then the use of the TLS protocol is required. 

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure. Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network. To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled. 

FIPS 140-2 approved TLS versions include TLS V1.0 or greater. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Verify that each frontend is configured with the following:

bind :<port> ssl crt <pemfile> ciphers FIPS:+3DES:!aNULL no-sslv3

Note: <port> and <pemfile> will be different for each frontend.

If the ciphers listed are not as shown above, this is a finding.'
  desc 'fix', "Navigate to and open the following files:

/etc/haproxy/conf.d/20-vcac.cfg
/etc/haproxy/conf.d/30-vro-config.cfg

Configure the bind option for each frontend with the following ciphers parameter:

'ciphers FIPS:+3DES:!aNULL'."
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43274r665290_chk'
  tag severity: 'medium'
  tag gid: 'V-240041'
  tag rid: 'SV-240041r879519_rule'
  tag stig_id: 'VRAU-HA-000015'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-43233r665291_fix'
  tag 'documentable'
  tag legacy: ['SV-100951', 'V-90301']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
