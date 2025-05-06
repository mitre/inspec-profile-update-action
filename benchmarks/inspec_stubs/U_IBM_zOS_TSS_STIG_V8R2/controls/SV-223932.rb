control 'SV-223932' do
  title 'The CA-TSS CANCEL Control Option must not be specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

The CANCEL Control Option allows security administrators to use the O/S CANCEL command to bring the TSS address space down.'
  desc 'check', 'From the ISPF Command enter:
TSS MODIFY STATUS

If the CANCEL Control Option is not specified, this is not a finding.'
  desc 'fix', 'Remove the CANCEL sub-option from the Control Options list.

TSS MODIFY(control_option [(suboption_list)])'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25605r516195_chk'
  tag severity: 'medium'
  tag gid: 'V-223932'
  tag rid: 'SV-223932r561402_rule'
  tag stig_id: 'TSS0-ES-000590'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25593r516196_fix'
  tag 'documentable'
  tag legacy: ['V-98571', 'SV-107675']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
