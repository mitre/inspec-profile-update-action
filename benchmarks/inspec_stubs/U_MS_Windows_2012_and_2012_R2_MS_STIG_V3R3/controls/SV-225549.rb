control 'SV-225549' do
  title 'The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group and other approved groups.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding:

Administrators

If the system serves the Remote Desktop Services role, the Remote Desktop Users group or another more restrictive group may be included.  

Organizations may grant this to other groups, such as more restrictive groups with administrative or management functions, if required.  Remote Desktop Services access must be restricted to the accounts that require it.  This must be documented with the ISSO.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to only include the following accounts or groups:

Administrators   

If the system serves the Remote Desktop Services role, the Remote Desktop Users group or another more restrictive group may be included.  

Organizations may grant this to other groups, such as more restrictive groups with administrative or management functions, if required.  Remote Desktop Services access must be restricted to the accounts that require it.  This must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27248r471989_chk'
  tag severity: 'medium'
  tag gid: 'V-225549'
  tag rid: 'SV-225549r569185_rule'
  tag stig_id: 'WN12-UR-000006-MS'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27236r471990_fix'
  tag 'documentable'
  tag legacy: ['SV-83319', 'V-26473']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
