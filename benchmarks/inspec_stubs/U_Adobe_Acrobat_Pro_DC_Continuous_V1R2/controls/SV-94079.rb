control 'SV-94079' do
  title 'Adobe Acrobat Pro DC Continuous privileged file and folder locations must be disabled.'
  desc 'Privileged Locations are the primary method Acrobat uses to allow users and admins to specify trusted content that should be exempt from security restrictions, such as when Enhanced Security is enabled.   A Privileged Location may be a file, folder, or a host.  If the user is allowed to set a Privileged Location, they could bypass security protections.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown

Value Name: bDisableTrustedFolders
Type: REG_DWORD
Value: 1

If the value for bDisableTrustedFolders is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Security (Enhanced) > In the 'Privileged Locations' section, verify 'Add Folder Path' option is greyed out (locked).  If this option is not greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Privileged folder locations' must be set to 'Disabled'. 

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown

Value Name: bDisableTrustedFolders
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > Security (Enhanced) > 'Privileged folder locations' to 'Disabled'. 

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-78987r3_chk'
  tag severity: 'medium'
  tag gid: 'V-79373'
  tag rid: 'SV-94079r1_rule'
  tag stig_id: 'AADC-CN-000840'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-86145r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
