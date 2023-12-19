control 'SV-253353' do
  title 'IPv6 source routing must be configured to highest protection.'
  desc 'Configuring the system to disable IPv6 source routing protects against spoofing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name: DisableIpSourceRouting

Value Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG package. "MSS-Legacy.admx" and "MSS-Legacy.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56806r829141_chk'
  tag severity: 'medium'
  tag gid: 'V-253353'
  tag rid: 'SV-253353r829143_rule'
  tag stig_id: 'WN11-CC-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56756r829142_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
