control 'SV-99959' do
  title 'Lighttpd must be configured with FIPS 140-2 compliant ciphers for https connections.'
  desc 'Transport Layer Security (TLS) is optional for a public web server. However, if authentication is being performed, then the use of the TLS protocol is required. 

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure. Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network. To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled. 

FIPS 140-2 approved TLS versions include TLS V1.0 or greater. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^ssl.cipher-list' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value returned in not "ssl.cipher-list = "FIPS: +3DES:!aNULL" "or is commented out, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following: 

ssl.cipher-list = "FIPS: +3DES:!aNULL"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-89001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89309'
  tag rid: 'SV-99959r1_rule'
  tag stig_id: 'VRAU-LI-000435'
  tag gtitle: 'SRG-APP-000416-WSR-000118'
  tag fix_id: 'F-96051r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
