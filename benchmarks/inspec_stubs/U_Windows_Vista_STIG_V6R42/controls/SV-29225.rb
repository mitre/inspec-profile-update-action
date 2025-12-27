control 'SV-29225' do
  title 'The amount of idle time required before suspending a session must be properly set.'
  desc 'Open sessions can increase the avenues of attack on a system.  This setting is used to control when a computer disconnects an inactive SMB session.  If client activity resumes, the session is automatically re-established.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Microsoft Network Server: Amount of idle time required before suspending session" is not set to "15" minutes or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

Value Name:  autodisconnect

Value Type:  REG_DWORD
Value:  0x0000000f (15) (or less)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Server: Amount of idle time required before suspending session" to "15" minutes or less.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-61999r1_chk'
  tag severity: 'low'
  tag gid: 'V-1174'
  tag rid: 'SV-29225r2_rule'
  tag gtitle: 'Idle Time Before Suspending a Session.'
  tag fix_id: 'F-66895r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
