control 'SV-248722' do
  title 'The OL 8 audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

'
  desc 'check', 'Verify OL 8 audits the execution of privileged functions. 
 
Check if OL 8 is configured to audit the execution of the "execve" system call, by running the following command: 
 
$ sudo grep execve /etc/audit/audit.rules 
 
-a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv 
 
-a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv 
 
If the command does not return all lines or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to audit the execution of the "execve" system call. 
 
Add or update the following file system rules to "/etc/audit/rules.d/audit.rules": 
 
-a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv 
 
-a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52156r779730_chk'
  tag severity: 'medium'
  tag gid: 'V-248722'
  tag rid: 'SV-248722r853794_rule'
  tag stig_id: 'OL08-00-030000'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-52110r779731_fix'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127']
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002234']
  tag nist: ['AC-6 (8)', 'AC-6 (9)']
end
