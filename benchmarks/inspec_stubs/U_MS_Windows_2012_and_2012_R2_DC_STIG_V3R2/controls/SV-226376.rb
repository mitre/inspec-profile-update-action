control 'SV-226376' do
  title 'The Create a token object user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Create a token object" user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Create a token object" user right, this is a finding.

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a token object" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28079r476974_chk'
  tag severity: 'high'
  tag gid: 'V-226376'
  tag rid: 'SV-226376r569184_rule'
  tag stig_id: 'WN12-UR-000012'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28067r476975_fix'
  tag 'documentable'
  tag legacy: ['SV-52113', 'V-26479']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
