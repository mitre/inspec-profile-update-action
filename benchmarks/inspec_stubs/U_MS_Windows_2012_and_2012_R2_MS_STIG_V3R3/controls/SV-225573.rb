control 'SV-225573' do
  title 'The Restore files and directories user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Restore files and directories" user right can circumvent file and directory permissions and could allow access to sensitive data.  It could also be used to overwrite more current data.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Restore files and directories" user right, this is a finding:

Administrators

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Restore files and directories" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27272r472061_chk'
  tag severity: 'medium'
  tag gid: 'V-225573'
  tag rid: 'SV-225573r569185_rule'
  tag stig_id: 'WN12-UR-000040'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27260r472062_fix'
  tag 'documentable'
  tag legacy: ['SV-52122', 'V-26504']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
