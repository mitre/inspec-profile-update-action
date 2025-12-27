control 'SV-48045' do
  title 'Local users must not exist on a system in a domain.'
  desc 'To minimize potential points of attack, local users, other than built-in accounts such as Administrator and Guest accounts, must not exist on a workstation in a domain.  Users must log onto workstations in a domain with their domain accounts.'
  desc 'check', 'Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
AcctDisabled
Groups

If local users other than the built-in accounts listed below exist on a workstation in a domain, this is a finding:

Built-in administrator account (SID ending in 500)
Built-in guest account (SID ending in 501)

If the organization has a need for special purpose local user accounts such as a backup administrator account (see V-14224), this must be documented with the ISSO.  This would not be a finding.'
  desc 'fix', 'Limit local user accounts on domain-joined systems.  Remove any unauthorized local accounts.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44784r3_chk'
  tag severity: 'low'
  tag gid: 'V-1148'
  tag rid: 'SV-48045r2_rule'
  tag stig_id: 'WN08-GE-000013'
  tag gtitle: 'Local Users Exist on a Workstation'
  tag fix_id: 'F-41183r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
