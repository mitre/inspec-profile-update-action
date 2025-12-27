control 'SV-213096' do
  title 'Adobe Acrobat Pro DC Classic access to unknown websites must be restricted.'
  desc 'Acrobat provides the ability for the user to store a list of websites with an associated behavior of allow, ask, or block. Websites that are not in this list are unknown. PDF files can contain URLs that will initiate connections to unknown websites in order to share or get information. That access must be restricted.'
  desc 'check', %q(Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following:
HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cDefaultLaunchURLPerms\

Value Name: iUnknownURLPerms
Type: REG_DWORD
Value: 3

If the value for iUnknownURLPerms is not set to "3" and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > Trust Manager > In the 'Internet Access from PDF Files outside the web browser' section > Select 'Change Settings' option >  In the 'PDF Files may connect to web sites to share or get information' section, if 'Block PDF files access to all web sites' is selected and greyed out (locked), then this is not a finding. If 'Custom setting' is checked, then in the 'Default behavior for web sites that are not in the above list' section,  verify the radio button 'Block access'  is checked and greyed out (locked) .  If the box is not checked nor greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Access to unknown websites' must be set to 'Enabled' and 'Block access' selected in the drop down box.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cDefaultLaunchURLPerms\

Value Name: iUnknownURLPerms
Type: REG_DWORD
Value: 3

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Access to unknown websites' to 'Enabled' and select 'Block access' in the drop down box.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14334r478113_chk'
  tag severity: 'low'
  tag gid: 'V-213096'
  tag rid: 'SV-213096r557504_rule'
  tag stig_id: 'AADC-CL-000280'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14332r478114_fix'
  tag 'documentable'
  tag legacy: ['V-80117', 'SV-94821']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
