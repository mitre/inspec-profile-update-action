control 'SV-223347' do
  title 'Outlook must use remote procedure call (RPC) encryption to communicate with Microsoft Exchange servers.'
  desc 'This policy setting controls whether Outlook uses remote procedure call (RPC) encryption to communicate with Microsoft Exchange servers. 

If you enable this policy setting, Outlook uses RPC encryption when communicating with an Exchange server. Note: RPC encryption only encrypts the data from the Outlook client computer to the Exchange server. It does not encrypt the messages themselves as they traverse the Internet. 

If you disable or do not configure this policy setting, RPC encryption is still used by default. This setting allows you to override the corresponding per-profile setting.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Account Settings >> Exchange >> Enable RPC encryption is set to "Enabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\rpc

If the value for enablerpcencryption is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Account Settings >> Exchange >> Enable RPC encryption to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25020r442260_chk'
  tag severity: 'medium'
  tag gid: 'V-223347'
  tag rid: 'SV-223347r879892_rule'
  tag stig_id: 'O365-OU-000002'
  tag gtitle: 'SRG-APP-000575'
  tag fix_id: 'F-25008r442261_fix'
  tag 'documentable'
  tag legacy: ['SV-108873', 'V-99769']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
