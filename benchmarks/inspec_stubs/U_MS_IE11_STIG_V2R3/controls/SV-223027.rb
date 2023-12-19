control 'SV-223027' do
  title 'Logon options must be configured to prompt (Internet zone).'
  desc "Users could submit credentials to servers operated by malicious individuals who could then attempt to connect to legitimate servers with those captured credentials. Care must be taken with user credentials, automatic logon performance, and how default Windows credentials are passed to the websites. This policy setting allows management of settings for logon options. If you enable this policy setting, you can choose from varying logon options. “Anonymous logon” disables HTTP authentication and uses the guest account only for the Common Internet File System (CIFS) protocol. “Prompt for user name and password” queries users for user IDs and passwords. After a user is queried, these values can be used silently for the remainder of the session. “Automatic logon only in Intranet zone” queries users for user IDs and passwords in other zones. After a user is queried, these values can be used silently for the remainder of the session. “Automatic logon with current user name and password” attempts logon using Windows NT Challenge Response. If Windows NT Challenge Response is supported by the server, the logon uses the user's network user name and password for login. If Windows NT Challenge Response is not supported by the server, the user is queried to provide the user name and password. If you disable this policy setting, logon is set to “Automatic logon only in Intranet zone”. If you do not configure this policy setting, logon is set to “Automatic logon only in Intranet zone”. The most secure option is to configure this setting to “Enabled”; “Anonymous logon”, but configuring this setting to “Enabled”; “Prompt for user name and password”, provides a reasonable balance between security and usability."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Logon options' must be 'Enabled', and 'Prompt for user name and password' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3 Criteria: If the value "1A00" is REG_DWORD = 65536 (decimal), this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Internet Zone -> 'Logon options' to 'Enabled', and select 'Prompt for user name and password' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24700r428631_chk'
  tag severity: 'medium'
  tag gid: 'V-223027'
  tag rid: 'SV-223027r428633_rule'
  tag stig_id: 'DTBI046-IE11'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-24688r428632_fix'
  tag 'documentable'
  tag legacy: ['SV-59387', 'V-46523']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
