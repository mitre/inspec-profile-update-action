control 'SV-253030' do
  title 'The TOSS audit system must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.

Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.

'
  desc 'check', 'Verify TOSS audits the execution of privileged functions.

Check if TOSS is configured to audit the execution of the "execve" system call, by running the following command:

$ sudo grep execve /etc/audit/audit.rules

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

If the command does not return all lines, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to audit the execution of the "execve" system call.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv 

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56483r824760_chk'
  tag severity: 'medium'
  tag gid: 'V-253030'
  tag rid: 'SV-253030r824762_rule'
  tag stig_id: 'TOSS-04-030860'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-56433r824761_fix'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127']
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002234']
  tag nist: ['AC-6 (8)', 'AC-6 (9)']
end
