control 'SV-207528' do
  title 'The VMM must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the VMM to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the VMM is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7785r365988_chk'
  tag severity: 'medium'
  tag gid: 'V-207528'
  tag rid: 'SV-207528r388482_rule'
  tag stig_id: 'SRG-OS-000480-VMM-002000'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-7785r365989_fix'
  tag 'documentable'
  tag legacy: ['V-57357', 'SV-71617']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
