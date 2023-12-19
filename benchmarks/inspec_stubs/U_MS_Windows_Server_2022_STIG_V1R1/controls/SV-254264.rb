control 'SV-254264' do
  title 'Windows Server 2022 must have the roles and features required by the system documented.'
  desc 'Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation.'
  desc 'check', 'Required roles and features will vary based on the function of the individual system.

Roles and features specifically required to be disabled per the STIG are identified in separate requirements.

If the organization has not documented the roles and features required for the system(s), this is a finding.

The PowerShell command "Get-WindowsFeature" will list all roles and features with an "Install State".'
  desc 'fix', 'Document the roles and features required for the system to operate. Uninstall any that are not required.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57749r848606_chk'
  tag severity: 'medium'
  tag gid: 'V-254264'
  tag rid: 'SV-254264r848608_rule'
  tag stig_id: 'WN22-00-000270'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-57700r848607_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
