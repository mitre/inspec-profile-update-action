control 'SV-228517' do
  title 'The Help Improve Proofing Tools feature for Office must be configured.'
  desc %q(The "Help Improve Proofing Tools" feature collects data about use of the Proofing Tools, such as additions to the custom dictionary, and sends it to Microsoft. After about six months, the feature stops sending data to Microsoft and deletes the data collection file from the user's computer. Although this feature does not intentionally collect personal information, some of the content sent could include items that were marked as spelling or grammar errors, such as proper names and account numbers. However, any numbers such as account numbers, street addresses, and phone numbers are converted to zeroes when the data is collected. Microsoft uses this information solely to improve the effectiveness of the Office Proofing Tools, not to identify users.
By default, this feature is enabled, if users choose to participate in the Customer Experience Improvement Program (CEIP). If an organization has policies that govern the use of external resources such as the CEIP, allowing the use of the "Help Improve Proofing Tools" feature might cause them to violate these policies.)
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Tools >> Options >> Spelling >> Proofing Data Collection "Improve Proofing Tools" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following. HKCU\Software\Policies\Microsoft\Office\15.0\common\ptwatson

If the value 'PTWOptIn' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Tools \\ Options \\ Spelling -> Proofing Data Collection "Improve Proofing Tools" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30750r498829_chk'
  tag severity: 'medium'
  tag gid: 'V-228517'
  tag rid: 'SV-228517r508020_rule'
  tag stig_id: 'DTOO182'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30735r498830_fix'
  tag 'documentable'
  tag legacy: ['V-17627', 'SV-52719']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
