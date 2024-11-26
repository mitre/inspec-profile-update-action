control 'SV-33502' do
  title 'RSS Feeds must be disallowed.'
  desc 'Users can subscribe to RSS feeds from within Outlook and read RSS items like e-mail messages. If your organization has policies that govern the use of external resources such as RSS feeds, allowing users to subscribe to the RSS feed in Outlook might enable them to violate those policies.'
  desc 'check', '==================================
NOTE:
Some operational environments may elect to allow use of RSS feeds integrated into Outlook, provided there is a mission need and the network environment meets the following criteria: 
- both the web site issuing the RSS feeds and the Outlook e-mail client both have an available network path to each other
- neither the web site issuing the RSS feeds nor the Outlook e-mail client have a network path to the public Internet.

An example of such an environment would be a closed lab or other deployed network where the requisite signoffs, artifacts, and network documentation demonstrate that the Public Internet is not available to the Outlook client, preventing unauthorized RSS subscriptions being accessed by users of the Outlook client. 

The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Turn off RSS feature” must be set to “Disabled”.

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\rss

Criteria: If the environment meets the above stated criteria, and value "Disable" is REG_DWORD = 0, this is not a finding.

For all environments where the Outlook e-mail client has access to public Internet web sites, RSS integration into Outlook is not permitted, and should be validated as follows. 
=================================

The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Turn off RSS feature” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\rss

Criteria: If the value Disable is REG_DWORD = 1, this is not a finding.'
  desc 'fix', '================================== 
NOTE:
If the use of RSS feeds integrated into Outlook is a mission need, and the network environment is configured with the following criteria: 
1. Both the web site issuing the RSS feeds and the Outlook e-mail client must both have an available network path to each other.
2. Neither the web site issuing the RSS feeds nor the Outlook e-mail client have a network path to the public Internet.

Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Turn off RSS feature” to “Disabled”.

For all environments where the Outlook e-mail clients have access to public Internet web sites, RSS integration into Outlook is not permitted, and should be configured as follows.
================================= 

Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Turn off RSS feature” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33986r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17808'
  tag rid: 'SV-33502r1_rule'
  tag stig_id: 'DTOO282 - Outlook'
  tag gtitle: 'DTOO282 - RSS Feeds'
  tag fix_id: 'F-29674r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
