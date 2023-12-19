control 'SV-217419' do
  title 'The BIG-IP appliance must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Verify the BIG-IP appliance is configured in accordance with the security configuration settings based on applicable DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If the BIG-IP appliance is not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to be in compliance with the applicable security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18644r290811_chk'
  tag severity: 'medium'
  tag gid: 'V-217419'
  tag rid: 'SV-217419r557520_rule'
  tag stig_id: 'F5BI-DM-000259'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-18642r290812_fix'
  tag 'documentable'
  tag legacy: ['V-60221', 'SV-74651']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
