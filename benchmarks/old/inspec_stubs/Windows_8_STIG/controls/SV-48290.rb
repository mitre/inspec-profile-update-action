control 'SV-48290' do
  title 'IP stateless autoconfiguration limits state must be enabled.'
  desc 'IP stateless autoconfiguration could configure routes that circumvent preferred routes if not limited.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: EnableIPAutoConfigurationLimits

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> Parameters -> "Set IP Stateless Autoconfiguration Limits State" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44968r1_chk'
  tag severity: 'low'
  tag gid: 'V-36673'
  tag rid: 'SV-48290r2_rule'
  tag stig_id: 'WN08-CC-000011'
  tag gtitle: 'WINCC-000011'
  tag fix_id: 'F-41425r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
