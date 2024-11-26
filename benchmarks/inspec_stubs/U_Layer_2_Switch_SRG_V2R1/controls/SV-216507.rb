control 'SV-216507' do
  title 'The layer 2 switch must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Determine if the switch is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If it is not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the switch to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-17742r298449_chk'
  tag severity: 'medium'
  tag gid: 'V-216507'
  tag rid: 'SV-216507r539569_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000100'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-17740r298450_fix'
  tag 'documentable'
  tag legacy: ['V-100097', 'SV-109201']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
