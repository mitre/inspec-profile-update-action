control 'SV-216508' do
  title 'The network device must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Determine if the network device is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If it is not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the network device to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-17743r382091_chk'
  tag severity: 'medium'
  tag gid: 'V-216508'
  tag rid: 'SV-216508r401224_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000317'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-4827r391865_fix'
  tag 'documentable'
  tag legacy: ['V-100099', 'SV-109203']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
