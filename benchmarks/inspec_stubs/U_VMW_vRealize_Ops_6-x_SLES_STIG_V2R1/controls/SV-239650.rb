control 'SV-239650' do
  title 'The SLES for vRealize must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Verify SLES for vRealize is configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs. 

If it is not, this is a finding.'
  desc 'fix', 'Configure SLES for vRealize in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42883r662399_chk'
  tag severity: 'medium'
  tag gid: 'V-239650'
  tag rid: 'SV-239650r662401_rule'
  tag stig_id: 'VROM-SL-001505'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42842r662400_fix'
  tag 'documentable'
  tag legacy: ['SV-99421', 'V-88771']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
