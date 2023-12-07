control 'SV-205677' do
  title 'Windows Server 2019 must have the roles and features required by the system documented.'
  desc 'Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation.'
  desc 'check', 'Required roles and features will vary based on the function of the individual system.

Roles and features specifically required to be disabled per the STIG are identified in separate requirements.

If the organization has not documented the roles and features required for the system(s), this is a finding.

The PowerShell command "Get-WindowsFeature" will list all roles and features with an "Install State".'
  desc 'fix', 'Document the roles and features required for the system to operate. Uninstall any that are not required.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5942r354949_chk'
  tag severity: 'medium'
  tag gid: 'V-205677'
  tag rid: 'SV-205677r569188_rule'
  tag stig_id: 'WN19-00-000270'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-5942r354950_fix'
  tag 'documentable'
  tag legacy: ['SV-103467', 'V-93381']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
