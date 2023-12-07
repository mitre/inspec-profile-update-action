control 'SV-225481' do
  title 'The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.'
  desc 'Allowing ICMP redirect of routes can lead to traffic not being routed properly.  When disabled, this forces ICMP to be routed via shortest path first.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: EnableICMPRedirect

Value Type: REG_DWORD
Value: 0'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes" to "Disabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27180r471785_chk'
  tag severity: 'low'
  tag gid: 'V-225481'
  tag rid: 'SV-225481r569185_rule'
  tag stig_id: 'WN12-SO-000039'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27168r471786_fix'
  tag 'documentable'
  tag legacy: ['SV-52925', 'V-4111']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
