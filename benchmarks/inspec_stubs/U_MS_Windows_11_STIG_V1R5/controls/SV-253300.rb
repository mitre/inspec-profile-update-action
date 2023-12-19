control 'SV-253300' do
  title 'The password history must be configured to 24 passwords remembered.'
  desc 'A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change a password to a unique password on a regularly scheduled basis. This enables users to effectively negate the purpose of mandating periodic password changes. The default value is 24 for Windows domain systems. DoD has decided this is the appropriate value for all Windows systems.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Enforce password history" is less than "24" passwords remembered, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Enforce password history" to "24" passwords remembered.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56753r828982_chk'
  tag severity: 'medium'
  tag gid: 'V-253300'
  tag rid: 'SV-253300r828984_rule'
  tag stig_id: 'WN11-AC-000020'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-56703r828983_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
