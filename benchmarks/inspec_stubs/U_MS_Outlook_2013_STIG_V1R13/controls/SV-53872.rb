control 'SV-53872' do
  title 'Access restriction settings for published calendars must be configured.'
  desc 'Users can share their calendars with others by publishing them to the Microsoft Office Online Calendar Sharing Services and to a server that supports the World Wide Web Distributed Authoring and Versioning (WebDAV) protocol. Office Online allows users to choose whether to restrict access to their calendars to people they invite, or allow unrestricted access to anyone who knows the URL to reach the calendar. DAV access restrictions can only be achieved through server and folder permissions, and might require the assistance of a server administrator to set up and maintain. 
If a calendar is visible to anyone on Office Online or third-party DAV servers, sensitive calendar information might be revealed.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Access to published calendars" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\pubcal

Criteria: If the value RestrictedAccessOnly is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Access to published calendars" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17546'
  tag rid: 'SV-53872r1_rule'
  tag stig_id: 'DTOO219'
  tag gtitle: 'DTOO219 - Access to Published Calendars'
  tag fix_id: 'F-46777r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
