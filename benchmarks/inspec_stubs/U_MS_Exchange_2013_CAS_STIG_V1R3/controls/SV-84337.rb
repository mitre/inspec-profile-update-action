control 'SV-84337' do
  title 'Exchange must use Encryption for RPC client access.'
  desc 'This setting controls whether client machines are forced to use secure channels to communicate with the server. If this feature is enabled, clients will only be able to communicate with the server over secure communication channels.

Failure to require secure connections to the client access server increases the potential for unintended eavesdropping or data loss.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-RpcClientAccess | Select Server, Name, EncryptionRequired

If the value of EncryptionRequired is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-RpcClientAccess -Server <ServerName> -EncryptionRequired $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70157r2_chk'
  tag severity: 'medium'
  tag gid: 'V-69715'
  tag rid: 'SV-84337r1_rule'
  tag stig_id: 'EX13-CA-000005'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-75919r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
