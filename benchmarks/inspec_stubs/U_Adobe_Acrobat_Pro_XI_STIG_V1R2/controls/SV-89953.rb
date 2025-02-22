control 'SV-89953' do
  title 'Adobe Acrobat Pro XI must be configured to block Flash Content.'
  desc 'Flash has a long history of vulnerabilities.  Although Flash is no longer provided with Acrobat, if the system has Flash installed, a malicious PDF could execute code on the system.  Configuring Flash to run from a privileged location limits the execution capability of untrusted Flash content that may be embedded in the PDF.'
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0

If the value for bEnableFlash is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75057r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75273'
  tag rid: 'SV-89953r1_rule'
  tag stig_id: 'ADBP-XI-000290'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81889r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
