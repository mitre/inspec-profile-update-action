control 'SV-48032' do
  title 'The password history must be configured to 24 passwords remembered.'
  desc 'A system is more vulnerable to unauthorized access when system users recycle the same password several times without being required to change a password to a unique password on a regularly scheduled basis.  This enables users to effectively negate the purpose of mandating periodic password changes.  The default value is 24 for Windows domain systems.  DoD has decided this is the appropriate value for all Windows systems.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies >> Password Policy.

If the value for "Enforce password history" is less than "24" passwords remembered, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Enforce password history" to "24" passwords remembered.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44770r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1107'
  tag rid: 'SV-48032r2_rule'
  tag stig_id: 'WN08-AC-000004'
  tag gtitle: 'Password Uniqueness'
  tag fix_id: 'F-41170r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
