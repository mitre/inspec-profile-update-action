control 'SV-226303' do
  title 'The system must be configured to prevent IP source routing.'
  desc 'Configuring the system to disable IP source routing protects against spoofing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: DisableIPSourceRouting

Value Type: REG_DWORD
Value: 2'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28005r476753_chk'
  tag severity: 'low'
  tag gid: 'V-226303'
  tag rid: 'SV-226303r794595_rule'
  tag stig_id: 'WN12-SO-000038'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27993r476754_fix'
  tag 'documentable'
  tag legacy: ['SV-52924', 'V-4110']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
