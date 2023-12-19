control 'SV-100847' do
  title 'The vAMI must restrict inbound connections from nonsecure zones.'
  desc 'Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify the application server configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk. Application servers utilize a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using ssh or some other form of approved cryptography. Application servers must have a capability to enable a secure remote admin capability. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^ssl.engine' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "ssl.engine" is not set to "enable", or is missing or is commented out, this is a finding.)
  desc 'fix', %q(Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Configure the lighttpd.conf file with the following value: 'ssl.engine = "enable"')
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89889r1_chk'
  tag severity: 'high'
  tag gid: 'V-90197'
  tag rid: 'SV-100847r1_rule'
  tag stig_id: 'VRAU-VA-000015'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-96939r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
