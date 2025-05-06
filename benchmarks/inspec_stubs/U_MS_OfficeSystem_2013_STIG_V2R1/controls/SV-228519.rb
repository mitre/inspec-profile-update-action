control 'SV-228519' do
  title 'Smart Documents use of Manifests in Office must be disallowed.'
  desc 'An XML expansion pack is the group of files that constitutes a Smart Document in Excel and Word. One or more components that provide the logic needed for a Smart Document are packaged by using an XML expansion pack. These components can include any type of file, including XML schemas, Extensible Stylesheet Language Transforms (XSLTs), dynamic-link libraries (DLLs), and image files, as well as additional XML files, HTML files, Word files, Excel files, and text files.
The key component to building an XML expansion pack is creating an XML expansion pack manifest file. By creating this file, the locations of all files that make up the XML expansion pack are specified, as well as information that instructs Office 2013 how to set up the files for the Smart Document. The XML expansion pack can also contain information about how to set up other files, such as how to install and register a COM object required by the XML expansion pack.
XML expansion packs can be used to initialize and load malicious code, which might affect the stability of a computer and lead to data loss. Office applications can load an XML expansion pack manifest file with a Smart Document.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Smart Documents (Word, Excel) "Disable Smart Document's use of manifests" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\Common\Smart Tag

If the value 'NeverLoadManifests' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Smart Documents (Word, Excel) "Disable Smart Document's use of manifests" to "Enabled".)
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30752r498835_chk'
  tag severity: 'medium'
  tag gid: 'V-228519'
  tag rid: 'SV-228519r508020_rule'
  tag stig_id: 'DTOO197'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30737r498836_fix'
  tag 'documentable'
  tag legacy: ['V-17669', 'SV-52746']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
