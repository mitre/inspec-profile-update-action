control 'SV-253481' do
  title 'The "Act as part of the operating system" user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access. Any accounts with this right can take complete control of a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts (to include administrators), are granted the "Act as part of the operating system" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56934r829525_chk'
  tag severity: 'high'
  tag gid: 'V-253481'
  tag rid: 'SV-253481r829527_rule'
  tag stig_id: 'WN11-UR-000015'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56884r829526_fix'
  tag 'documentable'
  tag cci: ['CCI-002205']
  tag nist: ['AC-4 (17)']
end
