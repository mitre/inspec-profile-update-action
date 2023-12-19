control 'SV-239864' do
  title 'The Cisco ASA must be configured to implement scanning threat detection.'
  desc 'In a port scanning attack, an unauthorized application is used to scan the host devices for available services and open ports for subsequent use in an attack. This type of scanning can be used as a DoS attack when the probing packets are sent excessively.'
  desc 'check', 'Review the ASA configuration to determine if scanning threat detection has been enabled.

threat-detection scanning-threat shun

If the ASA has not been configured to enable scanning threat detection, this is a finding.'
  desc 'fix', 'Configure scanning threat detection as shown in the example below.

ASA(config)# threat-detection scanning-threat shun'
  impact 0.7
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43097r665876_chk'
  tag severity: 'high'
  tag gid: 'V-239864'
  tag rid: 'SV-239864r665878_rule'
  tag stig_id: 'CASA-FW-000220'
  tag gtitle: 'SRG-NET-000362-FW-000028'
  tag fix_id: 'F-43056r665877_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
