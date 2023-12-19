control 'SV-33436' do
  title 'Internet links and Network UNCs created as embedded hyperlinks must be prevented.'
  desc 'When users type a string of characters, Excel recognizes as a Uniform Resource Locator (URL) or Uniform Naming Convention (UNC) path to a resource on the Internet or a local network, Excel will transform it into a hyperlink. Clicking the hyperlink opens it in the configured default Web browser or the appropriate application. This functionality can enable users to accidentally create links to dangerous or restricted resources, which could create a security risk.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Proofing -> Autocorrect Options “Internet and network paths as hyperlinks” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\options

If the value AutoHyperlink is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Proofing -> Autocorrect Options “Internet and network paths as hyperlinks” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17650'
  tag rid: 'SV-33436r1_rule'
  tag stig_id: 'DTOO138 - Excel'
  tag gtitle: 'DTOO138 - Internet and Network Path hyperlinks'
  tag fix_id: 'F-29608r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
