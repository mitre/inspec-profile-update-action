control 'SV-89981' do
  title 'Adobe Acrobat Pro XI privileged site locations must be disabled.'
  desc 'Privileged Locations are the primary method Acrobat uses to allow users and admins to specify trusted content that should be exempt from security restrictions, such as when Enhanced Security is enabled.

A Privileged Location may be a file, folder, or a host. If the user is allowed to set a Privileged Location, they could bypass security protections.'
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bDisableTrustedSites
Type: REG_DWORD
Value: 1

If the value for bDisableTrustedSites is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bDisableTrustedSites
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75085r1_chk'
  tag severity: 'low'
  tag gid: 'V-75301'
  tag rid: 'SV-89981r1_rule'
  tag stig_id: 'ADBP-XI-001325'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-81917r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
