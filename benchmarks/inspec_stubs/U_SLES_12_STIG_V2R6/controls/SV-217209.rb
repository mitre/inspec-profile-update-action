control 'SV-217209' do
  title 'The SUSE operating system must generate audit records for all uses of the privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

'
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

The audit daemon must be restarted for the changes to take effect.   

# sudo systemctl restart auditd.service'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18437r369783_chk'
  tag severity: 'low'
  tag gid: 'V-217209'
  tag rid: 'SV-217209r603262_rule'
  tag stig_id: 'SLES-12-020240'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-18435r369784_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000359-GPOS-00146', 'SRG-OS-000365-GPOS-00152']
  tag 'documentable'
  tag legacy: ['V-77323', 'SV-92019']
  tag cci: ['CCI-001877', 'CCI-001878', 'CCI-001914', 'CCI-001889', 'CCI-001875', 'CCI-001881', 'CCI-001882', 'CCI-001879', 'CCI-001880', 'CCI-001814', 'CCI-002234']
  tag nist: ['AU-7 a', 'AU-7 a', 'AU-12 (3)', 'AU-8 b', 'AU-7 a', 'AU-7 b', 'AU-7 b', 'AU-7 a', 'AU-7 a', 'CM-5 (1)', 'AC-6 (9)']
end
