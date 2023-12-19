control 'SV-224090' do
  title 'IBM z/OS Default profiles must not be defined in TSS OMVS UNIX security parameters for classified systems.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'If the system in not classified this is not applicable.

From a command line issue the following command:
TSS MODIFY STATUS
Note: One must have appropriate access to perform this command (have the site security officer to issue command).

If system is classified and UNIQUSER is off i.e., (UNIQUSER(OFF) this is not a finding.'
  desc 'fix', 'Ensure that Use of the OMVS default UIDs will not be allowed on any classified system.

Set Control Option UNIQUSER off.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25763r516669_chk'
  tag severity: 'medium'
  tag gid: 'V-224090'
  tag rid: 'SV-224090r561402_rule'
  tag stig_id: 'TSS0-US-000170'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25751r516670_fix'
  tag 'documentable'
  tag legacy: ['V-98887', 'SV-107991']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
