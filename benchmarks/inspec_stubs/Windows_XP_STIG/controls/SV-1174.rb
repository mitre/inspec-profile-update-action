control 'SV-1174' do
  title 'Amount of idle time required before suspending a session is improperly set.'
  desc 'Administrators should use this setting to control when a computer disconnects an inactive SMB session. If client activity resumes, the session is automatically reestablished.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Microsoft Network Server: Amount of idle time required before suspending a session” to ”15” minutes or less.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1174'
  tag rid: 'SV-1174r1_rule'
  tag gtitle: 'Idle Time Before Suspending a Session.'
  tag fix_id: 'F-5774r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
