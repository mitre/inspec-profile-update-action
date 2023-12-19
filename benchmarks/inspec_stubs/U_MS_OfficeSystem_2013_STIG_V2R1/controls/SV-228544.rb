control 'SV-228544' do
  title 'Relying on Vector markup Language (VML) for displaying graphics in browsers must be disallowed.'
  desc 'When saving documents as web pages, Excel, PowerPoint, and Word can save vector-based graphics in Vector Markup Language (VML), which enables Internet Explorer to display them smoothly at any resolution. By default, when saving VML graphics, Office applications also save copies of the graphics in a standard raster file format (GIF or PNG) for use by browsers that cannot display VML. If the "Rely on VML for displaying graphics in browsers" check box in the web Options dialog box is selected, applications will not save raster copies of VML graphics, which means those graphics will not display in non-Microsoft browsers.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Tools >> Options >> General >> Web Options >> Browsers "Rely on VML for displaying graphics in browsers" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\internet.

If the value 'RelyOnVML' is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Tools \\ Options \\ General \\ Web Options -> Browsers "Rely on VML for displaying graphics in browsers" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30777r498910_chk'
  tag severity: 'medium'
  tag gid: 'V-228544'
  tag rid: 'SV-228544r508020_rule'
  tag stig_id: 'DTOO180'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30762r498911_fix'
  tag 'documentable'
  tag legacy: ['V-17773', 'SV-52715']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
