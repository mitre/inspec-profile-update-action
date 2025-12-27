control 'SV-95659' do
  title 'AAA Services must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Determine if AAA Services are configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If AAA Services are not configured in accordance with the designated security configuration settings, this is a finding.'
  desc 'fix', 'Configure the network device to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80687r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80949'
  tag rid: 'SV-95659r1_rule'
  tag stig_id: 'SRG-APP-000516-AAA-000690'
  tag gtitle: 'SRG-APP-000516-AAA-000690'
  tag fix_id: 'F-87805r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
