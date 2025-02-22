control 'SV-221777' do
  title 'The Oracle Linux operating system must audit all executions of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify the operating system audits the execution of privileged functions using the following command:

# grep -iw execve /etc/audit/audit.rules

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.

If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.'
  desc 'fix', 'Configure the operating system to audit the execution of privileged functions.

Add or update the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36294r602476_chk'
  tag severity: 'medium'
  tag gid: 'V-221777'
  tag rid: 'SV-221777r603260_rule'
  tag stig_id: 'OL07-00-030360'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-36258r602477_fix'
  tag 'documentable'
  tag legacy: ['V-99293', 'SV-108397']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
