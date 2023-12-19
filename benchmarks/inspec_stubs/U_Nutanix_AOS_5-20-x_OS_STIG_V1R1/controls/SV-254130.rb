control 'SV-254130' do
  title 'Nutanix AOS must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Confirm Nutanix AOS is configured to audit the misuse of privileged commands.

$ sudo grep -iw execve /etc/audit/audit.rules
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.

If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to audit the misuse of privileged commands by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57615r846476_chk'
  tag severity: 'medium'
  tag gid: 'V-254130'
  tag rid: 'SV-254130r846478_rule'
  tag stig_id: 'NUTX-OS-000210'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-57566r846477_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
