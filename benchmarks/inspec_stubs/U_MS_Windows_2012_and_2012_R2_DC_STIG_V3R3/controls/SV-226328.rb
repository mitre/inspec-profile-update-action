control 'SV-226328' do
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords.  This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28030r476828_chk'
  tag severity: 'high'
  tag gid: 'V-226328'
  tag rid: 'SV-226328r794527_rule'
  tag stig_id: 'WN12-SO-000065'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-28018r476829_fix'
  tag 'documentable'
  tag legacy: ['SV-52892', 'V-3379']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
