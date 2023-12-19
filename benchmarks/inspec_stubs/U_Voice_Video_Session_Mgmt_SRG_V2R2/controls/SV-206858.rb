control 'SV-206858' do
  title 'The Voice Video Session Manager must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, Communication Tasking Orders (CTOs), and DTMs.'
  desc 'Configuring the network element to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network element. Security-related parameters are those parameters impacting the security state of the network element, including the parameters required to satisfy other security control requirements. For the network element, security-related parameters include settings for network traffic management configurations.'
  desc 'check', 'Verify the Voice Video Session Manager is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If the Voice Video Session Manager is not configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7113r459027_chk'
  tag severity: 'medium'
  tag gid: 'V-206858'
  tag rid: 'SV-206858r508661_rule'
  tag stig_id: 'SRG-NET-000512-VVSM-00050'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7113r459028_fix'
  tag 'documentable'
  tag legacy: ['V-62147', 'SV-76637']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
