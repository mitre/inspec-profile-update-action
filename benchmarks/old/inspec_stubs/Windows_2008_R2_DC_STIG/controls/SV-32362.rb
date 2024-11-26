control 'SV-32362' do
  title 'Optional Subsystems will not be permitted to operate on the system.'
  desc 'The POSIX subsystem is an Institute of Electrical and Electronic Engineers (IEEE) standard that defines a set of operating system services. The POSIX Subsystem is required if the server supports applications that use that subsystem. 
The subsystem introduces a security risk relating to processes that can potentially persist across logins. That is, if a user starts a process and then logs out, there is a potential that the next user who logs in to the system could access the previous users process. This is dangerous because the process started by the first user may retain that users system privileges; anything the second user does with that process will be performed with the privileges of the first user.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “System Settings: Optional Subsystems” has entries listed, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\Subsystems\\

Value Name:  Optional

Value Type:  REG_MULTI_SZ
Value:  (Blank)

Documentable: If an optional subsystem such as POSIX is required, then this needs to be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “System Settings: Optional Subsystems” to “Blank” (Configured with no entries).'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32760r1_chk'
  tag severity: 'low'
  tag gid: 'V-4445'
  tag rid: 'SV-32362r1_rule'
  tag gtitle: 'Optional Subsystems'
  tag fix_id: 'F-28835r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
