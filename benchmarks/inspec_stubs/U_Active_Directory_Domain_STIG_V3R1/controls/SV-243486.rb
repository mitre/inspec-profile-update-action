control 'SV-243486' do
  title 'The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group.'
  desc 'The Pre-Windows 2000 Compatible Access group was created to allow Windows NT domains to interoperate with AD domains by allowing unauthenticated access to certain AD data. The default permissions on many AD objects are set to allow access to the Pre-Windows 2000 Compatible Access group.

When the Anonymous Logon or Everyone groups are members of the Pre-Windows 2000 Compatible Access group, anonymous access to many AD objects is enabled.

Anonymous access to AD data could provide valuable account or configuration information to an intruder trying to determine the most effective attack strategies.'
  desc 'check', 'Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").
Expand the domain being reviewed in the left pane and select the "Builtin" container.
Double-click on the "Pre-Windows 2000 Compatible Access" group in the right pane.
Select the "Members" tab.

If the "Anonymous Logon" or "Everyone" groups are members, this is a finding.
(By default, these groups are not included in current Windows versions.)'
  desc 'fix', 'Ensure the "Anonymous Logon" and "Everyone" groups are not members of the "Pre-Windows 2000 Compatible Access group". (By default, these groups are not included in current Windows versions.)

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc").
Expand the domain being reviewed in the left pane and select the "Builtin" container.
Double-click on the "Pre-Windows 2000 Compatible Access" group in the right pane.
Select the "Members" tab.
If the "Anonymous Logon" or "Everyone" groups are members, select each and click "Remove".'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46761r723491_chk'
  tag severity: 'medium'
  tag gid: 'V-243486'
  tag rid: 'SV-243486r723493_rule'
  tag stig_id: 'AD.0220'
  tag gtitle: 'SRG-OS-000121'
  tag fix_id: 'F-46718r723492_fix'
  tag 'documentable'
  tag legacy: ['V-8547', 'SV-9044']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
