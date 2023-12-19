control 'SV-48164' do
  title 'The system must be configured to prevent the display of the last username on the logon screen.'
  desc 'Displaying the username of the last logged on user provides half of the userid/password equation that an unauthorized person would need to gain access.  The username of the last user to log onto a system must not be displayed.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Interactive logon: Do not display last user name" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: DontDisplayLastUserName

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Do not display last user name" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44864r1_chk'
  tag severity: 'low'
  tag gid: 'V-11806'
  tag rid: 'SV-48164r1_rule'
  tag stig_id: 'WN08-SO-000018'
  tag gtitle: 'Display of Last User Name'
  tag fix_id: 'F-41302r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
