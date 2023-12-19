control 'SV-239084' do
  title 'The Photon operating system must be configured to audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing all actions by superusers is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

'
  desc 'check', 'At the command line, execute the following command:

# auditctl -l | grep execve

Expected result:

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 execpriv

If the output does not match the expected result, this is a finding.

Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done as part of a separate control.'
  desc 'fix', 'Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the following lines:

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

At the command line, execute the following command:

# /sbin/augenrules --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42295r821353_chk'
  tag severity: 'medium'
  tag gid: 'V-239084'
  tag rid: 'SV-239084r821354_rule'
  tag stig_id: 'PHTN-67-000012'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-42254r816599_fix'
  tag satisfies: ['SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172']
  tag 'documentable'
  tag cci: ['CCI-000135', 'CCI-002884']
  tag nist: ['AU-3 (1)', 'MA-4 (1) (a)']
end
