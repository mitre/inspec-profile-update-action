control 'SV-253354' do
  title 'The system must be configured to prevent IP source routing.'
  desc 'Configuring the system to disable IP source routing protects against spoofing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 2'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG package. "MSS-Legacy.admx" and "MSS-Legacy.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56807r829144_chk'
  tag severity: 'medium'
  tag gid: 'V-253354'
  tag rid: 'SV-253354r829146_rule'
  tag stig_id: 'WN11-CC-000025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56757r829145_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
