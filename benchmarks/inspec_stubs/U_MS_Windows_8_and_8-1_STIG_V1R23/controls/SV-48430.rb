control 'SV-48430' do
  title 'IPv6 source routing must be configured to highest protection.'
  desc 'Configuring the system to disable IPv6 source routing protects against spoofing.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" is not set to "Highest protection, source routing is completely disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \System\CurrentControlSet\Services\Tcpip6\Parameters\

Value Name: DisableIpSourceRouting

Type: REG_DWORD
Value: 2)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to "Highest protection, source routing is completely disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45098r2_chk'
  tag severity: 'low'
  tag gid: 'V-21955'
  tag rid: 'SV-48430r2_rule'
  tag stig_id: 'WN08-SO-000037'
  tag gtitle: 'IPv6 Source Routing'
  tag fix_id: 'F-41560r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
