control 'SV-228466' do
  title 'RPC encryption between Outlook and Exchange server must be enforced.'
  desc 'This policy setting controls whether Outlook uses remote procedure call (RPC) encryption to communicate with Microsoft Exchange servers. If you enable this policy setting, Outlook uses RPC encryption when communicating with an Exchange server. Note - RPC encryption only encrypts the data from the Outlook client computer to the Exchange server. It does not encrypt the messages themselves as they traverse the Internet. If you disable or do not configure this policy setting, RPC encryption is still used by default.  This setting allows you to override the corresponding per-profile setting.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> Exchange "Enable RPC encryption" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\rpc

Criteria: If the value EnableRPCEncryption is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> Exchange "Enable RPC encryption" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30699r497720_chk'
  tag severity: 'medium'
  tag gid: 'V-228466'
  tag rid: 'SV-228466r508021_rule'
  tag stig_id: 'DTOO279'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-30684r497721_fix'
  tag 'documentable'
  tag legacy: ['SV-85877', 'V-71253']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
