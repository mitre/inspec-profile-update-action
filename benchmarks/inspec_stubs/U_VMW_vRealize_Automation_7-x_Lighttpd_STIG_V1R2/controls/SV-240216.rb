control 'SV-240216' do
  title 'Lighttpd must be configured with FIPS 140-2 compliant ciphers for https connections.'
  desc 'Transport Layer Security (TLS) is optional for a public web server. However, if authentication is being performed, then the use of the TLS protocol is required. 

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure. Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network. To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled. 

FIPS 140-2 approved TLS versions include TLS V1.0 or greater. NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^ssl.cipher-list' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value ssl.cipher-list = "FIPS: +3DES:!aNULL" is not returned or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

ssl.cipher-list = "FIPS: +3DES:!aNULL"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43449r667823_chk'
  tag severity: 'medium'
  tag gid: 'V-240216'
  tag rid: 'SV-240216r879519_rule'
  tag stig_id: 'VRAU-LI-000015'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-43408r667824_fix'
  tag 'documentable'
  tag legacy: ['SV-99871', 'V-89221']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
