control 'SV-100909' do
  title 'The vAMI sfcb must have HTTP disabled.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information. Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. The application server must utilize approved encryption when receiving transmitted data.'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'enableHttp:' /opt/vmware/etc/sfcb/sfcb.cfg | grep -v '^#'

If the value of "enableHttp" is set to "true", this is a finding.)
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'enableHttp: false'"
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90259'
  tag rid: 'SV-100909r1_rule'
  tag stig_id: 'VRAU-VA-000580'
  tag gtitle: 'SRG-APP-000442-AS-000259'
  tag fix_id: 'F-97001r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
