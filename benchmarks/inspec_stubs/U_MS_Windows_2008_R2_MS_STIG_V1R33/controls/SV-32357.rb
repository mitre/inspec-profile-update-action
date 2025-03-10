control 'SV-32357' do
  title 'The system will be configured to limit how often keep-alive packets are sent.'
  desc 'Controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds” is not set to “300000 or 5 minutes (recommended)” or less, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name: KeepAliveTime

Value Type:  REG_DWORD
Value:  300000'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds” to “300000 or 5 minutes (recommended)” or less.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32838r1_chk'
  tag severity: 'low'
  tag gid: 'V-4113'
  tag rid: 'SV-32357r1_rule'
  tag gtitle: 'TCP Connection Keep-Alive Time'
  tag fix_id: 'F-28004r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
