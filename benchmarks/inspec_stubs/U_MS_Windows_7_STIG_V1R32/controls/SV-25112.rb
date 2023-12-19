control 'SV-25112' do
  title 'System pagefile is cleared upon shutdown.'
  desc 'This check verifies that Windows is configured to not wipe clean the system pagefile during a controlled system shutdown.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Shutdown: Clear virtual memory pagefile” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\

Value Name:  ClearPageFileAtShutdown

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Shutdown: Clear virtual memory pagefile” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-41r1_chk'
  tag severity: 'low'
  tag gid: 'V-1084'
  tag rid: 'SV-25112r1_rule'
  tag gtitle: 'Clear System Pagefile'
  tag fix_id: 'F-6897r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
