control 'SV-4117' do
  title 'The system is configured to allow SYN attacks.'
  desc 'Adjusts retransmission of TCP SYN-ACKs. When enabled, connection responses time out more quickly in the event of a SYN DoS attack.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)” is not set to “Connections time out sooner if a SYN attack is detected”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

Value Name:  SynAttackProtect

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)” to “Connections time out sooner if a SYN attack is detected”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-314r1_chk'
  tag severity: 'low'
  tag gid: 'V-4117'
  tag rid: 'SV-4117r1_rule'
  tag gtitle: 'SYN Attack Protection'
  tag fix_id: 'F-5725r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
