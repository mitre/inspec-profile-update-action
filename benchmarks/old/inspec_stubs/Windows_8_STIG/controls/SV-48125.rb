control 'SV-48125' do
  title 'The system must be configured to limit how often keep-alive packets are sent.'
  desc 'This setting controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact.  A higher value could allow an attacker to cause a denial of service with numerous connections.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" is not set to "300000 or 5 minutes (recommended)" or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: KeepAliveTime

Value Type: REG_DWORD
Value: 300000)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" to "300000 or 5 minutes (recommended)" or less.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44851r1_chk'
  tag severity: 'low'
  tag gid: 'V-4113'
  tag rid: 'SV-48125r1_rule'
  tag stig_id: 'WN08-SO-000041'
  tag gtitle: 'TCP Connection Keep-Alive Time'
  tag fix_id: 'F-41262r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
