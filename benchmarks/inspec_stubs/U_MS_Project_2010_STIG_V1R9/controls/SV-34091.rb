control 'SV-34091' do
  title 'Untrusted intranet zone access to Project servers must not be allowed.'
  desc 'Enabling this setting allows users to access Project Server websites and workspaces outside of the trusted Internet zone.  As a result, malicious code could become active on user computers or the network to gain access to sensitive data.  In this situation, the site could attempt to capture personal information, like passwords and user names.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Project 2010 -> Project Options -> Security “Enable untrusted intranet zone access to Project server” must be set to “Disabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\ms project\\security

Criteria: If the value TrustWSS is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2010 -> Project Options -> Security “Enable untrusted intranet zone access to Project server” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Project 2010'
  tag check_id: 'C-34359r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26691'
  tag rid: 'SV-34091r1_rule'
  tag stig_id: 'DTOO346 - Project'
  tag gtitle: 'DTOO346 - Untrusted intranet zone access'
  tag fix_id: 'F-29998r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
