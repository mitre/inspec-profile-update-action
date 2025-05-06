control 'SV-253272' do
  title 'Standard local user accounts must not exist on a system in a domain.'
  desc 'To minimize potential points of attack, local user accounts, other than built-in accounts and local administrator accounts, must not exist on a workstation in a domain. Users must log onto workstations in a domain with their domain accounts.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.

If local users other than the accounts listed below exist on a workstation in a domain, this is a finding.

Built-in Administrator account (Disabled)
Built-in Guest account (Disabled)
Built-in DefaultAccount (Disabled)
Built-in defaultuser0 (Disabled)
Built-in WDAGUtilityAccount (Disabled)
Local administrator account(s)

All of the built-in accounts may not exist on a system, depending on the Windows 11 version.'
  desc 'fix', 'Limit local user accounts on domain-joined systems. Remove any unauthorized local accounts.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56725r828898_chk'
  tag severity: 'low'
  tag gid: 'V-253272'
  tag rid: 'SV-253272r828900_rule'
  tag stig_id: 'WN11-00-000085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56675r828899_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
