control 'SV-54059' do
  title 'User Entries to Server List must be disallowed.'
  desc "If users are able to manually enter the addresses of servers that are not approved by the organization, they could use servers that do not meet your organization's information security requirements, which could cause sensitive information to be at risk.
By default, when users create a meeting workspace, they can choose a server from a default list provided by administrators or manually enter the address of a server that is not listed."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Meeting Workspace "Disable user entries to server list" is set to "Enabled (Publish default, disallow others)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\meetings\\profile

Criteria: If the value ServerUI is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Meeting Workspace "Disable user entries to server list" to "Enabled (Publish default, disallow others)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17944'
  tag rid: 'SV-54059r1_rule'
  tag stig_id: 'DTOO286'
  tag gtitle: 'DTOO286 - Disable User Entries to Server list'
  tag fix_id: 'F-46939r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
