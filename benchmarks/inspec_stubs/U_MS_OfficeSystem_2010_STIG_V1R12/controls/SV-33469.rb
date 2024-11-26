control 'SV-33469' do
  title 'Hyperlink warnings for Office must be configured for use.'
  desc 'Unsafe hyperlinks are links that might pose a security risk if users click them. Clicking an unsafe link could compromise the security of sensitive information or harm the computer.
Links that Office considers unsafe include links to executable files, TIFF files, and Microsoft Document Imaging (MDI) files. Other unsafe links are those using protocols considered to be unsafe, including msn, nntp, mms, outlook, and stssync.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Suppress hyperlink warnings” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security

Criteria: If the value DisableHyperLinkWarning is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings “Suppress hyperlink warnings” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33952r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17659'
  tag rid: 'SV-33469r1_rule'
  tag stig_id: 'DTOO194 - Office System'
  tag gtitle: 'DTOO194 - Hyperlink warnings for Office'
  tag fix_id: 'F-29641r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
