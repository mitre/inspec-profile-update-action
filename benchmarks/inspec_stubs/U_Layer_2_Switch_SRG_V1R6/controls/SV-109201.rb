control 'SV-109201' do
  title 'The layer 2 switch must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Determine if the switch is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If it is not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the switch to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-98949r1_chk'
  tag severity: 'medium'
  tag gid: 'V-100097'
  tag rid: 'SV-109201r1_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000100'
  tag gtitle: 'SRG-NET-000512-L2S-000100'
  tag fix_id: 'F-105783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
