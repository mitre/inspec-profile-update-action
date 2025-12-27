control 'SV-228432' do
  title 'Access restriction settings for published calendars must be configured.'
  desc 'This policy setting determines what restrictions apply to users who publish their calendars on Office.com or third-party World Wide Web Distributed Authoring and Versioning (WebDAV) servers. If you enable or disable this policy setting, calendars that are published on Office.com must have restricted access (users other than the calendar owner/publisher who wish to view the calendar can only do so if they receive invitations from the calendar owner), and users cannot publish their calendars to third-party DAV servers. If you do not configure this policy setting, users can share their calendars with others by publishing them to the Office.com Calendar Sharing Services and to a server that supports the World Wide Web Distributed Authoring and Versioning (WebDAV) protocol. Office.com allows users to choose whether to restrict access to their calendars to people they invite, or allow unrestricted access to anyone who knows the URL to reach the calendar. DAV access restrictions can only be achieved through server and folder permissions, and might require the assistance of a server administrator to set up and maintain.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Access to published calendars" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\pubcal

Criteria: If the value RestrictedAccessOnly is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Access to published calendars" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30665r497618_chk'
  tag severity: 'medium'
  tag gid: 'V-228432'
  tag rid: 'SV-228432r508021_rule'
  tag stig_id: 'DTOO219'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30650r497619_fix'
  tag 'documentable'
  tag legacy: ['SV-85759', 'V-71135']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
