control 'SV-225547' do
  title 'The Act as part of the operating system user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups (to include administrators), are granted the "Act as part of the operating system" user right, this is a finding.

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27246r471983_chk'
  tag severity: 'high'
  tag gid: 'V-225547'
  tag rid: 'SV-225547r569185_rule'
  tag stig_id: 'WN12-UR-000003'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27234r471984_fix'
  tag 'documentable'
  tag legacy: ['SV-52108', 'V-1102']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
