control 'SV-213139' do
  title 'Adobe Acrobat Pro DC Continuous privileged host locations must be disabled.'
  desc 'Privileged Locations are the primary method Acrobat uses to allow users and admins to specify trusted content that should be exempt from security restrictions, such as when Enhanced Security is enabled.  A Privileged Location may be a file, folder, or a host. If the user is allowed to set a Privileged Location, they could bypass security protections.'
  desc 'check', "Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bDisableTrustedSites
Type: REG_DWORD
Value: 1

If the value for bDisableTrustedSites is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Security (Enhanced) > In the 'Privileged Locations' section, verify 'Add Host' option is greyed out (locked).  If the option is not greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Privileged host locations' must be set to 'Disabled'."
  desc 'fix', "Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\DC\\FeatureLockDown

Value Name: bDisableTrustedSites
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Privileged host locations' to 'Disabled'."
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14376r766569_chk'
  tag severity: 'low'
  tag gid: 'V-213139'
  tag rid: 'SV-213139r766571_rule'
  tag stig_id: 'AADC-CN-001325'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-14374r766570_fix'
  tag 'documentable'
  tag legacy: ['SV-94109', 'V-79403']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
