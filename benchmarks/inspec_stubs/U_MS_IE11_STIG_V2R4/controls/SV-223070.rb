control 'SV-223070' do
  title 'Logon options must be configured and enforced (Restricted Sites zone).'
  desc "Users could submit credentials to servers operated by malicious individuals who could then attempt to connect to legitimate servers with those captured credentials. Care must be taken with user credentials, automatic logon performance, and how default Windows credentials are passed to the websites. This policy setting allows management of settings for logon options. If you enable this policy setting, you can choose from varying logon options. “Anonymous logon” disables HTTP authentication and uses the guest account only for the Common Internet File System (CIFS) protocol. “Prompt for user name and password” queries users for user IDs and passwords. After a user is queried, these values can be used silently for the remainder of the session. “Automatic logon only in Intranet zone” queries users for user IDs and passwords in other zones. After a user is queried, these values can be used silently for the remainder of the session. “Automatic logon with current user name and password” attempts logon using Windows NT Challenge Response. If Windows NT Challenge Response is supported by the server, the logon uses the user's network user name and password for login. If Windows NT Challenge Response is not supported by the server, the user is queried to provide the user name and password. If you disable this policy setting, logon is set to “Automatic logon only in Intranet zone”. If you do not configure this policy setting, logon is set to “Automatic logon only in Intranet zone”. The most secure option is to configure this setting to “Enabled”; “Anonymous logon”. This will prevent users from submitting credentials to servers in this security zone."
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Logon options' must be 'Enabled', and 'Anonymous logon' selected from the drop-down box. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4 Criteria: If the value "1A00" is REG_DWORD = 196608 (decimal), this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> 'Logon options' to 'Enabled', and select 'Anonymous logon' from the drop-down box."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24743r428760_chk'
  tag severity: 'medium'
  tag gid: 'V-223070'
  tag rid: 'SV-223070r879636_rule'
  tag stig_id: 'DTBI136-IE11'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-24731r428761_fix'
  tag 'documentable'
  tag legacy: ['SV-59471', 'V-46607']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
