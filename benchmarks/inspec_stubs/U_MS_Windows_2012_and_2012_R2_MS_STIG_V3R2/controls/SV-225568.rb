control 'SV-225568' do
  title 'The Lock pages in memory user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause performance issues or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Lock pages in memory" user right, this is a finding.

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Lock pages in memory" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27267r472046_chk'
  tag severity: 'medium'
  tag gid: 'V-225568'
  tag rid: 'SV-225568r569185_rule'
  tag stig_id: 'WN12-UR-000029'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27255r472047_fix'
  tag 'documentable'
  tag legacy: ['SV-52119', 'V-26494']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
