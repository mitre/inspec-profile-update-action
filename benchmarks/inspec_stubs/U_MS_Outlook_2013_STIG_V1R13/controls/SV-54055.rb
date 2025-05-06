control 'SV-54055' do
  title 'RSS Feeds must be disallowed.'
  desc 'Users can subscribe to RSS feeds from within Outlook and read RSS items like email messages. If an organization has policies that govern the use of external resources such as RSS feeds, allowing users to subscribe to the RSS feed in Outlook will enable them to violate those policies.'
  desc 'check', 'NOTE:
Some operational environments may elect to allow use of RSS feeds integrated into Outlook, provided there is a mission need and the network environment meets the following criteria: 

- Both the website issuing the RSS feeds and the Outlook email client have an available network path to each other.
- Neither the website issuing the RSS feeds nor the Outlook email client has a network path to the public Internet.

An example of such an environment would be a closed lab or other deployed network where the requisite signoffs, artifacts, and network documentation demonstrate that the public Internet is not available to the Outlook client, preventing unauthorized RSS subscriptions being accessed by users of the Outlook client. 

If the environment meets the above stated criteria, this requirement is Not Applicable.

For all environments where the Outlook email client has access to public Internet websites, RSS integration into Outlook is not permitted, and should be validated as follows: 

The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> RSS Feeds "Turn off RSS feature" is set to "Enabled".

When this policy setting is enabled, the RSS aggregation feature in Outlook is disabled.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\rss

Criteria: If the REG_DWORD value for "Disable" is 1, this is not a finding.'
  desc 'fix', 'NOTE:
If the use of RSS feeds integrated into Outlook is a mission need, and the network environment is configured with the following criteria: 
1. Both the website issuing the RSS feeds and the Outlook email client must have an available network path to each other.
2. Neither the website issuing the RSS feeds nor the Outlook email client has a network path to the public Internet.

Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> RSS Feeds "Turn off RSS feature" to "Enabled".

For all environments where the Outlook email clients have access to public Internet websites, RSS integration into Outlook is not permitted, and should be configured as follows:
================================= 

Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> RSS Feeds "Turn off RSS feature" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47995r7_chk'
  tag severity: 'medium'
  tag gid: 'V-17808'
  tag rid: 'SV-54055r2_rule'
  tag stig_id: 'DTOO282'
  tag gtitle: 'DTOO282 - RSS Feeds'
  tag fix_id: 'F-46935r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
