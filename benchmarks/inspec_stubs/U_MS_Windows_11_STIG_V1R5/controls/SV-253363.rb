control 'SV-253363' do
  title 'Windows 11 must be configured to prioritize ECC Curves with longer key lengths first.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. By default Windows uses ECC curves with shorter key lengths first. Requiring ECC curves with longer key lengths to be prioritized first helps ensure more secure algorithms are used.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002\\

Value Name: EccCurves

Value Type: REG_MULTI_SZ
Value: NistP384 NistP256'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> SSL Configuration Settings >> "ECC Curve Order" to "Enabled" with "ECC Curve Order:" including the following in the order listed:

NistP384
NistP256'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56816r829171_chk'
  tag severity: 'medium'
  tag gid: 'V-253363'
  tag rid: 'SV-253363r829173_rule'
  tag stig_id: 'WN11-CC-000052'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-56766r829172_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
