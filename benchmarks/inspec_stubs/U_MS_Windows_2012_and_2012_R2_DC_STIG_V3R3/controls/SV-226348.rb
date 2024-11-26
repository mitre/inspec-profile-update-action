control 'SV-226348' do
  title 'Optional Subsystems must not be permitted to operate on the system.'
  desc 'The POSIX subsystem is an Institute of Electrical and Electronic Engineers (IEEE) standard that defines a set of operating system services.  The POSIX Subsystem is required if the server supports applications that use that subsystem.  The subsystem introduces a security risk relating to processes that can potentially persist across logins.  That is, if a user starts a process and then logs out, there is a potential that the next user who logs in to the system could access the previous users process.  This is dangerous because the process started by the first user may retain that users system privileges, and anything the second user does with that process will be performed with the privileges of the first user.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\Subsystems\\

Value Name: Optional

Value Type: REG_MULTI_SZ
Value: (Blank)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System settings: Optional subsystems" to "Blank" (Configured with no entries).'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28050r476888_chk'
  tag severity: 'low'
  tag gid: 'V-226348'
  tag rid: 'SV-226348r794632_rule'
  tag stig_id: 'WN12-SO-000088'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-28038r476889_fix'
  tag 'documentable'
  tag legacy: ['V-4445', 'SV-52219']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
