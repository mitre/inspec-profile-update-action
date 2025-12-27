control 'SV-225482' do
  title 'The system must be configured to limit how often keep-alive packets are sent.'
  desc 'This setting controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact.  A higher value could allow an attacker to cause a denial of service with numerous connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: KeepAliveTime

Value Type: REG_DWORD
Value: 300000 (or less)'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" to "300000 or 5 minutes (recommended)" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27181r471788_chk'
  tag severity: 'low'
  tag gid: 'V-225482'
  tag rid: 'SV-225482r852254_rule'
  tag stig_id: 'WN12-SO-000041'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-27169r471789_fix'
  tag 'documentable'
  tag legacy: ['SV-52927', 'V-4113']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
