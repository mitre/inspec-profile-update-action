control 'SV-33493' do
  title 'RPC encryption between Outlook and Exchange server must be enforced.'
  desc 'The remote procedure call (RPC) communication channel between an Outlook client computer and an Exchange server is not encrypted. If a malicious person is able to eavesdrop on the network traffic between Outlook and the server, they might be able to access confidential information.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Exchange “Enable RPC encryption” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\rpc

Criteria: If the value EnableRPCEncryption is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Exchange “Enable RPC encryption” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33976r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17615'
  tag rid: 'SV-33493r1_rule'
  tag stig_id: 'DTOO279 - Outlook'
  tag gtitle: 'DTOO279 - Enable RPC Encryption'
  tag fix_id: 'F-29660r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
