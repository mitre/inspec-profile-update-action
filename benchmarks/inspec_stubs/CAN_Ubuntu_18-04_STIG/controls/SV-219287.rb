control 'SV-219287' do
  title 'The Ubuntu operating system must generate audit records upon successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, however, by combining syscalls into one rule whenever possible.'
  desc 'check', %q(Verify the Ubuntu operating system generates audit records upon successful/unsuccessful use of "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep 'unlink\|rename\|rmdir'

-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k delete

If the command does not return audit rules for the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls or the lines are commented out, this is a finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
The "-k" allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate audit events upon successful/unsuccessful use of "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -Fauid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k delete

Notes: For 32-bit architectures, only the 32-bit specific entries are required. 
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

To reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21012r809524_chk'
  tag severity: 'medium'
  tag gid: 'V-219287'
  tag rid: 'SV-219287r809526_rule'
  tag stig_id: 'UBTU-18-010375'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-21011r809525_fix'
  tag 'documentable'
  tag legacy: ['V-100797', 'SV-109901']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
