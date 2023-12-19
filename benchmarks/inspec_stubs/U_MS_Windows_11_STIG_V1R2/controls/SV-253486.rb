control 'SV-253486' do
  title 'The "Create a token object" user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Create a token object" user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Create a token object" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a token object" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56939r829540_chk'
  tag severity: 'high'
  tag gid: 'V-253486'
  tag rid: 'SV-253486r829542_rule'
  tag stig_id: 'WN11-UR-000045'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56889r829541_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
