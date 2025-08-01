control 'SV-53234' do
  title 'Untrusted intranet zone access to Project servers must not be allowed.'
  desc 'Enabling this setting allows users to access Project server websites and workspaces outside of the trusted Internet zone.  As a result, malicious code could become active on user computers or the network to gain access to sensitive data.  In this situation, the site could attempt to capture personal information, such as passwords and user names.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2013 -> Project Options -> Security "Enable untrusted intranet zone access to Project server" is set to "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\ms project\\security

Criteria: If the value TrustWSS is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Project 2013 -> Project Options -> Security "Enable untrusted intranet zone access to Project server" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Project 2013'
  tag check_id: 'C-47541r1_chk'
  tag severity: 'medium'
  tag gid: 'V-40892'
  tag rid: 'SV-53234r1_rule'
  tag stig_id: 'DTOO346'
  tag gtitle: 'DTOO346 - Untrusted intranet zone'
  tag fix_id: 'F-46161r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
