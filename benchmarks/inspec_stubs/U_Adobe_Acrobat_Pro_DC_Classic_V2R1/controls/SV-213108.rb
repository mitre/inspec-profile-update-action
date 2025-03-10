control 'SV-213108' do
  title 'Adobe Acrobat Pro DC Classic Cloud Synchronization must be disabled.'
  desc 'By default, Adobe online services are tightly integrated in Adobe Acrobat. When the Adobe Cloud synchronization is disabled it prevents the synchronization of desktop preferences across devices on which the user is signed in with an Adobe ID (including phones).'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1

If the value for bTogglePrefsSync is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Cloud Synchronization' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cServices

Value Name: bTogglePrefsSync
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Cloud Synchronization' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14346r478143_chk'
  tag severity: 'medium'
  tag gid: 'V-213108'
  tag rid: 'SV-213108r557504_rule'
  tag stig_id: 'AADC-CL-001290'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14344r478144_fix'
  tag 'documentable'
  tag legacy: ['V-80141', 'SV-94845']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
