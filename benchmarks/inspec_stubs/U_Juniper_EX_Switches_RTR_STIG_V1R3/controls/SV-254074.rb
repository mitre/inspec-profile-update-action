control 'SV-254074' do
  title 'The Juniper router must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Determine if the router is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If it is not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the router to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57526r844253_chk'
  tag severity: 'medium'
  tag gid: 'V-254074'
  tag rid: 'SV-254074r844255_rule'
  tag stig_id: 'JUEX-RT-001020'
  tag gtitle: 'SRG-NET-000512-RTR-000100'
  tag fix_id: 'F-57477r844254_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
