control 'SV-248790' do
  title 'OL 8 must generate audit records for any use of the "chown", "fchown", "fchownat", and "lchown" system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
Audit records can be generated from various components within the information system (e.g., module or policy filter).
The "chown" command is used to change file owner and group.
The "fchown" system call is used to change the ownership of a file referred to by the open file descriptor.
The "fchownat" system call is used to change ownership of a file relative to a directory file descriptor.
The "lchown" system call is used to change the ownership of the file specified by a path, which does not dereference symbolic links.

When a user logs on, the AUID is set to the UID of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to "-1". The AUID representation is an unsigned 32-bit integer, which equals "4294967295". The audit system interprets "-1", "4294967295", and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall that all programs on the system makes. Therefore, it is very important to only use syscall rules when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. Performance can be helped, though, by combining syscalls into one rule whenever possible.

'
  desc 'check', 'Verify OL 8 generates an audit record for any use of the "chown", "fchown", "fchownat", and "lchown" system calls by running the following command to check the file system rules in "/etc/audit/audit.rules": 
 
$ sudo grep chown /etc/audit/audit.rules 
 
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng 
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng 
 
If audit rules are not defined for "chown", "fchown", "fchownat", and "lchown" or any of the lines returned are commented out, this is a finding.  
 
Note: The "-k" allows for specifying an arbitrary identifier, and the string after it does not need to match the example output above.'
  desc 'fix', 'Configure the audit system to generate an audit event for any use of the "chown", "fchown", "fchownat", and "lchown" system calls by adding or updating the following line to "/etc/audit/rules.d/audit.rules": 
 
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng 
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_chng 
 
The audit daemon must be restarted for the changes to take effect. To restart the audit daemon, run the following command: 
 
$ sudo service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52224r818679_chk'
  tag severity: 'medium'
  tag gid: 'V-248790'
  tag rid: 'SV-248790r853828_rule'
  tag stig_id: 'OL08-00-030480'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-52178r818680_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
