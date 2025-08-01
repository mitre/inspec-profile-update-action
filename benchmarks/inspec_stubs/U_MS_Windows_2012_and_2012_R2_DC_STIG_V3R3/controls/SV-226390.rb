control 'SV-226390' do
  title 'The Increase scheduling priority user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Increase scheduling priority" user right can change a scheduling priority causing performance issues or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Increase scheduling priority" user right, this is a finding:

Administrators

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Increase scheduling priority" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28093r477016_chk'
  tag severity: 'medium'
  tag gid: 'V-226390'
  tag rid: 'SV-226390r794662_rule'
  tag stig_id: 'WN12-UR-000027'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28081r477017_fix'
  tag 'documentable'
  tag legacy: ['SV-52118', 'V-26492']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
