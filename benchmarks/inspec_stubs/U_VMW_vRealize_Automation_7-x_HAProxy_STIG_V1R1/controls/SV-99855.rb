control 'SV-99855' do
  title 'HAProxy must be configured with FIPS 140-2 compliant ciphers for https connections.'
  desc 'Transport Layer Security (TLS) is optional for a public web server. However, if authentication is being performed, then the use of the TLS protocol is required. 

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure. Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network. To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled. 

FIPS 140-2 approved TLS versions include TLS V1.0 or greater. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', %q(At the command prompt, execute the following command:
 
grep -En 'ciphers' /etc/haproxy/conf.d/*.cfg
 
If two lines are not returned, this is a finding. 

If the values for "ciphers" are not set to "FIPS:+3DES:!aNULL", this is a finding.)
  desc 'fix', 'Navigate to and open /etc/haproxy/conf.d/30-vro-config.cfg

Navigate to and configure the "frontend https-in-vro-config" section with the following value:  

bind :8283 ssl crt /opt/vmware/etc/lighttpd/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3

Navigate to and open /etc/haproxy/conf.d/20-vcac.cfg

Navigate to and configure the "frontend https-in" section with the following value:  

bind 0.0.0.0:443 ssl crt /etc/apache2/server.pem ciphers FIPS:+3DES:!aNULL no-sslv3'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89205'
  tag rid: 'SV-99855r1_rule'
  tag stig_id: 'VRAU-HA-000410'
  tag gtitle: 'SRG-APP-000416-WSR-000118'
  tag fix_id: 'F-95947r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
