control 'SV-33475' do
  title 'Smart Documents use of Manifests in Office must be disallowed.'
  desc 'An XML expansion pack is the group of files that constitutes a Smart Document in Excel and Word. You package one or more components that provide the logic needed for a Smart Document by using an XML expansion pack. These components can include any type of file, including XML schemas, Extensible Stylesheet Language Transforms (XSLTs), dynamic-link libraries (DLLs), and image files, as well as additional XML files, HTML files, Word files, Excel files, and text files.
The key component to building an XML expansion pack is creating an XML expansion pack manifest file. By creating this file, you specify the locations of all files that make up the XML expansion pack, as well as information that instructs 2007 Office how to set up the files for your Smart Document. The XML expansion pack can also contain information about how to set up some files, such as how to install and register a COM object required by the XML expansion pack.
XML expansion packs can be used to initialize and load malicious code, which might affect the stability of a computer and lead to data loss. Office applications can load an XML expansion pack manifest file with a Smart Document.'
  desc 'check', "The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Smart Documents (Word, Excel) “Disable Smart Document's use of manifests” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\Common\\Smart Tag

Criteria: If the value NeverLoadManifests is REG_DWORD = 1, this is not a finding."
  desc 'fix', "Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Smart Documents (Word, Excel) “Disable Smart Document's use of manifests” to “Enabled”."
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33958r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17669'
  tag rid: 'SV-33475r1_rule'
  tag stig_id: 'DTOO197 - Office System'
  tag gtitle: 'DTOO197 - Document Manifests'
  tag fix_id: 'F-29647r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
