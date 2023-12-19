control 'SV-85501' do
  title 'Smart Documents use of Manifests in Office must be disallowed.'
  desc 'This policy setting controls whether Office 2016 applications can load an XML expansion pack manifest file with a Smart Document. An XML expansion pack is the group of files that constitutes a Smart Document in Excel and Word. You package one or more components that provide the logic needed for a Smart Document by using an XML expansion pack. These components can include any type of file, including XML schemas, Extensible Stylesheet Language Transforms (XSLTs), dynamic-link libraries (DLLs), and image files, as well as additional XML files, HTML files, Word files, Excel files, and text files. The key component to building an XML expansion pack is creating an XML expansion pack manifest file. By creating this file, you specify the locations of all files that make up the XML expansion pack, as well as information that instructs Office 2016 how to set up the files for your Smart Document. The XML expansion pack can also contain information about how to set up some files, such as how to install and register a COM object required by the XML expansion pack. If you enable this policy setting, Office 2016 applications cannot load XML expansion packs with Smart Documents. If you disable or do not configure this policy setting, Office 2016 applications can load an XML expansion pack manifest file with a Smart Document.'
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Smart Documents (Word, Excel) "Disable Smart Document's use of manifests" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\Common\Smart Tag

Criteria: If the value NeverLoadManifests is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Smart Documents (Word, Excel) "Disable Smart Document's use of manifests" to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-71321r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70877'
  tag rid: 'SV-85501r1_rule'
  tag stig_id: 'DTOO197'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
