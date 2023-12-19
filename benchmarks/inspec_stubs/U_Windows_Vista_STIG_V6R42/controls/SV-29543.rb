control 'SV-29543' do
  title 'A Windows system has a writable DCOM configuration.'
  desc 'A registry key for a valid DCOM object has access permissions that could allow non-administrator users to change the security settings if inadvertently set to a low level of security.  An attacker could possibly execute code under the context of the console or some other user.'
  desc 'check', 'Verify the permissions of the following registry key and its subkeys:

HKLM\\Software\\Classes\\Appid

If any standard (non-privileged) user accounts or groups have greater than “read” access, then this would be a finding.

The default permissions are acceptable.  At the Appid level they are as follows and will be inherited by many of the subkeys.

Creator Owner - Special (Full)
Administrators - Full
SYSTEM - Full
Users - Read

Vista subkeys that have Trusted Installer with “Full” permissions are acceptable.  These will typically have lesser permissions of "Read" for Administrators and System.'
  desc 'fix', 'Fortify DCOMs AppId permissions.  Any changes should be thoroughly tested so objects continue to function under tightened security.
- Open the Registry Editor.
- Navigate to HKEY_LOCAL_MACHINE\\Software\\Classes\\Appid.
- Select the application that generated this vulnerability.
- Set the permissions for standard (non-privileged) user accounts or groups to Read only.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-39216r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6826'
  tag rid: 'SV-29543r1_rule'
  tag gtitle: 'DCOM - Object Registry Permission'
  tag fix_id: 'F-6513r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
