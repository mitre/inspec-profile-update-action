control 'SV-33479' do
  title 'Vector markup Language (VML) for displaying graphics in browsers must be disallowed.'
  desc 'When saving documents as Web pages, Excel, PowerPoint, and Word can save vector–based graphics in Vector Markup Language (VML), which enables Internet Explorer to display them smoothly at any resolution. By default, when saving VML graphics, Office applications also save copies of the graphics in a standard raster file format (GIF or PNG) for use by browsers that cannot display VML. If the Rely on VML for displaying graphics in browsers check box in the Web Options dialog box is selected, applications will not save raster copies of VML graphics, which means those graphics will not display in non-Microsoft browsers.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options -> Browsers “Rely on VML for displaying graphics in browsers” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value RelyOnVML is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options -> Browsers “Rely on VML for displaying graphics in browsers” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33962r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17773'
  tag rid: 'SV-33479r1_rule'
  tag stig_id: 'DTOO180 - Office System'
  tag gtitle: 'DTOO180 - Vector Markup Lang (VML) / IE graphics'
  tag fix_id: 'F-29651r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
