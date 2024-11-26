control 'SV-251722' do
  title 'The SUSE operating system must generate audit records for all uses of the unlink, unlinkat, rename, renameat and rmdir syscalls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls.

Verify that the following command call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

> sudo grep 'unlink\|rename\|rmdir' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S unlink, unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink, unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete

If both the "b32" and "b64" audit rules are not defined for the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S unlink, unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink, unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete

The audit daemon must be restarted for the changes to take effect.

> sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-55159r809533_chk'
  tag severity: 'medium'
  tag gid: 'V-251722'
  tag rid: 'SV-251722r809534_rule'
  tag stig_id: 'SLES-12-020411'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-55113r809455_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
