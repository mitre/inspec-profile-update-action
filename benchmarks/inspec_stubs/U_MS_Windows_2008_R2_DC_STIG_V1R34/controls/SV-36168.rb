control 'SV-36168' do
  title 'The Server Operators group must have the ability to schedule jobs by means of the AT command disabled.'
  desc 'This policy controls the ability of members of the local Server Operators group to schedule AT jobs. If disabled, only administrators can schedule jobs that use AT commands. Unlike Scheduled Tasks which require you to specify the credential under which the task will run, AT jobs run under the authority of whatever account the AT service runs (SYSTEM by default). Non administrators who can schedule AT commands, thus have a means to elevate their privileges.  Although this setting is disabled, Server Operators will still be able to schedule jobs using Task Scheduler.'
  desc 'check', '1. Analyze the system using the Security Configuration and  Analysis snap-in.  

2. Expand the Security Configuration and Analysis tree view.

3. Navigate to Local Policies and select Security Options.

4. If the value for “Domain Controller: Allow server operators to schedule tasks” is not set to “Disabled”, then this is a finding.'
  desc 'fix', 'Set the value for “Domain Controller: Allow server operators to schedule tasks” to “Disabled”.

The policy referenced configures the following registry value:
Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\
Value Name:  SubmitControl
Value Type:  REG_DWORD
Value:  0'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32082r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2373'
  tag rid: 'SV-36168r1_rule'
  tag stig_id: 'AD.3058_2008_R2'
  tag gtitle: 'Task Scheduling - Server Operators'
  tag fix_id: 'F-28439r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
