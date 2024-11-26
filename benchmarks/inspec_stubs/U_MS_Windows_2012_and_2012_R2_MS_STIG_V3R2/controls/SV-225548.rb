control 'SV-225548' do
  title 'The Allow log on locally user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on locally" user right can log on interactively to a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on locally" user right, this is a finding:

Administrators

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on locally" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27247r471986_chk'
  tag severity: 'medium'
  tag gid: 'V-225548'
  tag rid: 'SV-225548r569185_rule'
  tag stig_id: 'WN12-UR-000005'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27235r471987_fix'
  tag 'documentable'
  tag legacy: ['SV-52110', 'V-26472']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
