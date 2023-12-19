control 'SV-213097' do
  title 'Adobe Acrobat Pro DC Classic access to websites must be blocked.'
  desc 'PDF files can contain URLs that initiate connections to websites in order to share or get information. Any Internet access introduces a security risk as malicious websites can transfer harmful content or silently gather data.'
  desc 'check', %q(Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following:
HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cDefaultLaunchURLPerms\

Value Name: iURLPerms
Type: REG_DWORD
Value: 1

If the value for iURLPerms is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Setting the value for iURLPerms to "0" means that a custom settings has been selected.  Custom setting allows for specific websites to be used for PDF workflows.  These websites must be approved by the ISSO/AO otherwise the setting must be "1" which blocks access to all websites.  If the iURLPerms setting is "0" and a documented risk acceptance approving the websites is provided, this is not a finding.

GUI path: Edit > Preferences > Trust Manager > In the 'Internet Access from PDF Files outside the web browser' section > Select 'Change Settings' option > In the 'PDF Files may connect to web sites to share or get information' section > Verify the radio button 'Block PDF files access to all web sites' is selected and greyed out (locked).    If 'Custom setting' is checked, a documented risk acceptance approved by the ISSO/AO approving the websites must be provided and then this is not a finding. 

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Access to websites' must be set to 'Enabled' and 'Block PDF files access to all web sites' selected in the drop down box. If 'Custom setting' is selected, a documented risk acceptance approved by the ISSO/AO approving the websites must be provided and then this is not a finding. 

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cDefaultLaunchURLPerms\

Value Name: iURLPerms
Type: REG_DWORD
Value: 1

The setting may be set to "0" if a documented risk acceptance approving the websites is approved by the ISSO/AO.

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > Trust Manager > 'Access to websites' to 'Enabled' and select 'Block PDF files access to all web sites' in the drop down box.  Select 'Custom setting' if needed and provide a documented risk acceptance approved by the ISSO/AO approving the websites. 

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14335r478116_chk'
  tag severity: 'low'
  tag gid: 'V-213097'
  tag rid: 'SV-213097r557504_rule'
  tag stig_id: 'AADC-CL-000285'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14333r478117_fix'
  tag 'documentable'
  tag legacy: ['V-80119', 'SV-94823']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
