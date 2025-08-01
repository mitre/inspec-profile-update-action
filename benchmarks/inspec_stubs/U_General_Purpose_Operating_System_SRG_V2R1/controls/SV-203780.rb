control 'SV-203780' do
  title 'The operating system must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify the operating system is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs. If it is not, this is a finding.'
  desc 'fix', 'Configure the operating system in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3905r375731_chk'
  tag severity: 'medium'
  tag gid: 'V-203780'
  tag rid: 'SV-203780r388482_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00227'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-3905r375732_fix'
  tag 'documentable'
  tag legacy: ['SV-70851', 'V-56591']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
