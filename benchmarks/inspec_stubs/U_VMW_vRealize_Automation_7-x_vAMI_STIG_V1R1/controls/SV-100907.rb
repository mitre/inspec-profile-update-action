control 'SV-100907' do
  title 'The vAMI sfcb must have HTTPS enabled.'
  desc 'Preventing the disclosure or modification of transmitted information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. If data in transit is unencrypted, it is vulnerable to disclosure and modification. If approved cryptographic algorithms are not used, encryption strength cannot be assured. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'enableHttps:' /opt/vmware/etc/sfcb/sfcb.cfg | grep -v '^#'

If the value of "enableHttps" is missing or is not set to "true", this is a finding.)
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'enableHttps: true'"
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89949r2_chk'
  tag severity: 'medium'
  tag gid: 'V-90257'
  tag rid: 'SV-100907r1_rule'
  tag stig_id: 'VRAU-VA-000570'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-96999r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
