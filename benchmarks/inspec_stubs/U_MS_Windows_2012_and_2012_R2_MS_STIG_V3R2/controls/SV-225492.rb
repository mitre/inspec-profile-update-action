control 'SV-225492' do
  title 'Anonymous enumeration of SAM accounts must not be allowed.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27191r471818_chk'
  tag severity: 'high'
  tag gid: 'V-225492'
  tag rid: 'SV-225492r569185_rule'
  tag stig_id: 'WN12-SO-000051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27179r471819_fix'
  tag 'documentable'
  tag legacy: ['SV-53122', 'V-26283']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
