control 'SV-220715' do
  title 'Standard local user accounts must not exist on a system in a domain.'
  desc 'To minimize potential points of attack, local user accounts, other than built-in accounts and local administrator accounts, must not exist on a workstation in a domain.  Users must log onto workstations in a domain with their domain accounts.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Users.

If local users other than the accounts listed below exist on a workstation in a domain, this is a finding.

Built-in Administrator account (Disabled)
Built-in Guest account (Disabled)
Built-in DefaultAccount (Disabled)
Built-in defaultuser0 (Disabled)
Built-in WDAGUtilityAccount (Disabled)
Local administrator account(s)

All of the built-in accounts may not exist on a system, depending on the Windows 10 version.'
  desc 'fix', 'Limit local user accounts on domain-joined systems.  Remove any unauthorized local accounts.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22430r554630_chk'
  tag severity: 'low'
  tag gid: 'V-220715'
  tag rid: 'SV-220715r569187_rule'
  tag stig_id: 'WN10-00-000085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22419r554631_fix'
  tag 'documentable'
  tag legacy: ['SV-77857', 'V-63367']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
