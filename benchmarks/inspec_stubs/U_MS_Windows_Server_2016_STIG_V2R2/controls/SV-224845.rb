control 'SV-224845' do
  title 'The roles and features required by the system must be documented.'
  desc 'Unnecessary roles and features increase the attack surface of a system. Limiting roles and features of a system to only those necessary reduces this potential. The standard installation option (previously called Server Core) further reduces this when selected at installation.'
  desc 'check', 'Required roles and features will vary based on the function of the individual system.

Roles and features specifically required to be disabled per the STIG are identified in separate requirements.

If the organization has not documented the roles and features required for the system(s), this is a finding.

The PowerShell command "Get-WindowsFeature" will list all roles and features with an "Install State".'
  desc 'fix', 'Document the roles and features required for the system to operate. Uninstall any that are not required.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26536r465437_chk'
  tag severity: 'medium'
  tag gid: 'V-224845'
  tag rid: 'SV-224845r569186_rule'
  tag stig_id: 'WN16-00-000300'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26524r465438_fix'
  tag 'documentable'
  tag legacy: ['SV-87929', 'V-73277']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
