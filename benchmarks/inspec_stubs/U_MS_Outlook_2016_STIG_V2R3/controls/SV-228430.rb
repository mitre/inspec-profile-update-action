control 'SV-228430' do
  title 'Publishing to a Web Distributed and Authoring (DAV) server must be prevented.'
  desc 'This policy setting controls whether Outlook users can publish their calendars to a DAV server. If you enable this policy setting, Outlook users cannot publish their calendars to a DAV server. If you disable or do not configure this policy setting, Outlook users can share their calendars with others by publishing them to a server that supports the World Wide Web Distributed Authoring and Versioning (WebDAV) protocol.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Prevent publishing to a DAV server" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\pubcal

Criteria: If the value DisableDav is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Prevent publishing to a DAV server" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30663r497612_chk'
  tag severity: 'medium'
  tag gid: 'V-228430'
  tag rid: 'SV-228430r508021_rule'
  tag stig_id: 'DTOO217'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30648r497613_fix'
  tag 'documentable'
  tag legacy: ['SV-85755', 'V-71131']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
