control 'SV-223939' do
  title 'The CA-TSS LUUPDONCE Control Option value specified must be set to NO.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS MODIFY STATUS

If the LUUPDONCE Control Option value is set to "YES", this is a finding.'
  desc 'fix', 'Configure LUUPDONCE control option is set to (NO). Evaluate the impact associated with implementation of the control option. Develop a plan of action to set the control option setting to NO and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25612r516216_chk'
  tag severity: 'medium'
  tag gid: 'V-223939'
  tag rid: 'SV-223939r877780_rule'
  tag stig_id: 'TSS0-ES-000660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25600r516217_fix'
  tag 'documentable'
  tag legacy: ['SV-107689', 'V-98585']
  tag cci: ['CCI-000366', 'CCI-002251']
  tag nist: ['CM-6 b', 'AC-9 (4)']
end
