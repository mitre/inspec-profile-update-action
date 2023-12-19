control 'SV-226302' do
  title 'IPv6 source routing must be configured to the highest protection level.'
  desc 'Configuring the system to disable IPv6 source routing protects against spoofing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

Value Name: DisableIPSourceRouting

Type: REG_DWORD
Value: 2'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28004r476750_chk'
  tag severity: 'low'
  tag gid: 'V-226302'
  tag rid: 'SV-226302r794594_rule'
  tag stig_id: 'WN12-SO-000037'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27992r476751_fix'
  tag 'documentable'
  tag legacy: ['SV-53180', 'V-21955']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
