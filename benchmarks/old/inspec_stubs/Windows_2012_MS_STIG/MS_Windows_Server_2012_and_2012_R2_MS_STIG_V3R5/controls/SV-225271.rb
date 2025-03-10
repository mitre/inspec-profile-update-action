control 'SV-225271' do
  title 'The minimum password age must meet requirements.'
  desc 'Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database.  This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for the "Minimum password age" is set to "0" days ("Password can be changed immediately."), this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum password age" to at least "1" day.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26970r471155_chk'
  tag severity: 'medium'
  tag gid: 'V-225271'
  tag rid: 'SV-225271r569185_rule'
  tag stig_id: 'WN12-AC-000006'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-26958r471156_fix'
  tag 'documentable'
  tag legacy: ['V-1105', 'SV-52852']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
