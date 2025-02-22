control 'SV-213122' do
  title 'Adobe Acrobat Pro DC Continuous must be configured to block Flash Content.'
  desc 'Flash has a long history of vulnerabilities.  Although Flash is no longer provided with Acrobat, if the system has Flash installed, a malicious PDF could execute code on the system.  Configuring Flash to run from a privileged location limits the execution capability of untrusted Flash content that may be embedded in the PDF.'
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0

If the value for bEnableFlash is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Enable Flash' must be set to 'Disabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Enable Flash' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14359r766524_chk'
  tag severity: 'medium'
  tag gid: 'V-213122'
  tag rid: 'SV-213122r766526_rule'
  tag stig_id: 'AADC-CN-000290'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14357r766525_fix'
  tag 'documentable'
  tag legacy: ['SV-94075', 'V-79369']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
