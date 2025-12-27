control 'SV-43979' do
  title 'Encryption must be used for RPC client access.'
  desc 'This setting controls whether client machines are forced to use secure channels to communicate with the server.  If this feature is enabled, clients will only be able to communicate with the server over secure communication channels.

Failure to require secure connections to the client access server increases the potential for unintended eavesdropping or data loss.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-RpcClientAccess | Select Server, EncryptionRequired

If the value of 'EncryptionRequired' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RpcClientAccess  -Server <'ServerName'> -EncryptionRequired $true"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33559'
  tag rid: 'SV-43979r1_rule'
  tag stig_id: 'Exch-1-002'
  tag gtitle: 'Exch-1-002'
  tag fix_id: 'F-37451r1_fix'
  tag 'documentable'
end
