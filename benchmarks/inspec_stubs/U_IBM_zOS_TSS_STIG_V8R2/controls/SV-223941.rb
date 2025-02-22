control 'SV-223941' do
  title 'CA-TSS RECOVER Control Option must be set to ON.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the RECOVER Control Option value is not set to "RECOVER(ON)", this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the following control option setting as specified and proceed with the change. 

RECOVER(ON)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25614r516222_chk'
  tag severity: 'medium'
  tag gid: 'V-223941'
  tag rid: 'SV-223941r561402_rule'
  tag stig_id: 'TSS0-ES-000680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25602r516223_fix'
  tag 'documentable'
  tag legacy: ['V-98589', 'SV-107693']
  tag cci: ['CCI-000550', 'CCI-000366']
  tag nist: ['CP-10', 'CM-6 b']
end
