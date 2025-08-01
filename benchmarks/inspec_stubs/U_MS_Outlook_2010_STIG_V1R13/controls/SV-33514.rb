control 'SV-33514' do
  title 'Publishing to a Web Distributed and Authoring (DAV) server must be prevented.'
  desc "Outlook users can share their calendars with others by publishing them to a server that supports the World Wide Web Distributed Authoring and Versioning (WebDAV) protocol. Unlike the Microsoft Office Online Calendar Sharing Service, which allows users to manage other people's access to their calendars, DAV access restrictions can only be accomplished through server and folder permissions, and might require the assistance of the server administrator to set up and maintain. If these permissions are not managed properly, unauthorized people could access sensitive information."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service “Prevent publishing to a DAV server” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\pubcal

Criteria: If the value DisableDav is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service “Prevent publishing to a DAV server” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17762'
  tag rid: 'SV-33514r1_rule'
  tag stig_id: 'DTOO217 - Outlook'
  tag gtitle: 'DTOO217 - Prevent publishing to DAV Servers'
  tag fix_id: 'F-29689r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
