control 'SV-226145' do
  title 'IP stateless autoconfiguration limits state must be enabled.'
  desc 'IP stateless autoconfiguration could configure routes that circumvent preferred routes if not limited.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: EnableIPAutoConfigurationLimits

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> Parameters -> "Set IP Stateless Autoconfiguration Limits State" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27847r475758_chk'
  tag severity: 'low'
  tag gid: 'V-226145'
  tag rid: 'SV-226145r794495_rule'
  tag stig_id: 'WN12-CC-000011'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27835r475759_fix'
  tag 'documentable'
  tag legacy: ['SV-51605', 'V-36673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
