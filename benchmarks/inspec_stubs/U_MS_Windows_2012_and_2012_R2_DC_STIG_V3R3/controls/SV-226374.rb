control 'SV-226374' do
  title 'The Back up files and directories user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Back up files and directories" user right can circumvent file and directory permissions and could allow access to sensitive data.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Back up files and directories" user right, this is a finding:

Administrators

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Back up files and directories" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28077r476968_chk'
  tag severity: 'medium'
  tag gid: 'V-226374'
  tag rid: 'SV-226374r794651_rule'
  tag stig_id: 'WN12-UR-000007'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28065r476969_fix'
  tag 'documentable'
  tag legacy: ['SV-52111', 'V-26474']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
