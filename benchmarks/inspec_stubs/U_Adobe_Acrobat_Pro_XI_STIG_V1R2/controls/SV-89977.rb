control 'SV-89977' do
  title 'Adobe Acrobat Pro XI certified document trust must be disabled.'
  desc "Certified document trust elevates signed PDF files to a privileged location and bypasses privileged view security protections. Disabling certified documents disables and locks the end user's ability to elevate certified documents as a privileged location."
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bEnableCertificateBasedTrust
Type: REG_DWORD
Value: 0

If the value for bEnableCertificateBasedTrust is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bEnableCertificateBasedTrust
Type: REG_DWORD
Value: 0'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75297'
  tag rid: 'SV-89977r1_rule'
  tag stig_id: 'ADBP-XI-001335'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-81913r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
