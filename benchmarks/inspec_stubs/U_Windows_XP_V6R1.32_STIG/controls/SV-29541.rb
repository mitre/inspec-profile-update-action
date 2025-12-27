control 'SV-29541' do
  title 'A Windows system has a writable DCOM configuration.'
  desc 'A registry key for a valid DCOM object has access permissions that allow non-administrator users to change the security settings. If DCOM security settings are inadvertently set to a low level of security, it may be possible for an attacker to execute code, possibly under the user context of the console user.In addition, an attacker could change the security on the object to allow for a future attack, such as setting the object to run as Interactive User. The Interactive User runs the application using the security context of the user currently logged on to the computer. If this option is selected and the user is not logged on, then the application will not start.'
  desc 'check', '·Using the Registry Editor, go to the following Registry key:

HKLM\\Software\\Classes\\Appid(inherited by all subkeys)

Administrators    Full
SYSTEM             Full
Users	      Read

·If any account other than Administrators and System has greater than “read” access, then this would be a finding.

·Select each subkey and verify that it is inheriting the same permissions.
·If any subkey has permissions that are less strict than those above, then this would be a finding.'
  desc 'fix', 'Fortify DCOMs AppId permissions.  Any changes should be thoroughly tested so objects continue to function under tightened security.
- Open the Registry Editor.
- Navigate to HKEY_LOCAL_MACHINE\\Software\\Classes\\Appid.
- Select the application that generated this vulnerability.
- Set the permissions for standard (non-privileged) user accounts or groups to Read only.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-3103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6826'
  tag rid: 'SV-29541r1_rule'
  tag gtitle: 'DCOM - Object Registry Permission'
  tag fix_id: 'F-6513r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
