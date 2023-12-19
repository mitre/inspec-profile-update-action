control 'SV-226351' do
  title 'Domain controllers must be configured to allow reset of machine account passwords.'
  desc 'Enabling this setting on all domain controllers in a domain prevents domain members from changing their computer account passwords.  If these passwords are weak or compromised, the inability to change them may leave these computers vulnerable.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

Value Name: RefusePasswordChange

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain controller: Refuse machine account password changes" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28053r476897_chk'
  tag severity: 'low'
  tag gid: 'V-226351'
  tag rid: 'SV-226351r794683_rule'
  tag stig_id: 'WN12-SO-000091-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28041r476898_fix'
  tag 'documentable'
  tag legacy: ['SV-51141', 'V-4408']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
