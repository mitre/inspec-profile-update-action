control 'SV-248774' do
  title 'OL 8 must generate audit records for any use of the "rename", "unlink", "rmdir", "renameat", and "unlinkat" system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).
The "rename" system call will rename the specified files by replacing the first occurrence of expression in their name by replacement.
The "unlink" system call deletes a name from the filesystem.  If that name was the last link to a file and no processes have the file open, the file is deleted and the space it was using is made available for reuse.
The "rmdir" system call removes empty directories.
The "renameat" system call renames a file, moving it between directories, if required.
The "unlinkat" system call operates in exactly the same way as either "unlink" or "rmdir" except for the differences described in the manual page.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. Performance can be helped, though, by combining syscalls into one rule whenever possible.

'
  desc 'check', %q(Verify OL 8 is configured to generate audit records for any use of the "rename", "unlink", "rmdir", "renameat", and "unlinkat" system calls by running the following command: 
 
$ sudo grep 'rename\|unlink\|rmdir' /etc/audit/audit.rules 
 
-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete 
-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F auid>=1000 -F auid!=unset -k delete 
 
If the command does not return an audit rule for "rename", "unlink", "rmdir", "renameat" and "unlinkat" or any of the lines returned are commented out, this is a finding. 
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure OL 8 to generate audit records for any use of the "rename", "unlink", "rmdir", "renameat", and "unlinkat" system calls by adding or updating the following lines to "/etc/audit/rules.d/audit.rules": 
 
-a always,exit -F arch=b32 -S rename,unlink,rmdir,renameat,unlinkat -F success=1 -F auid>=1000 -F auid!=unset -k delete  
 
-a always,exit -F arch=b64 -S rename,unlink,rmdir,renameat,unlinkat -F success=1 -F auid>=1000 -F auid!=unset -k delete 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52208r818673_chk'
  tag severity: 'medium'
  tag gid: 'V-248774'
  tag rid: 'SV-248774r818675_rule'
  tag stig_id: 'OL08-00-030361'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52162r818674_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
