control 'SV-219257' do
  title 'The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary since these affect performance. The more rules, the bigger the performance hit. The performance is helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', %q(Verify the Ubuntu operating system generates an audit record upon unsuccessful attempts to use the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls.

Check the configured audit rules with the following commands:

# sudo auditctl -l | grep 'open\|truncate\|creat'

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access

If the command does not return audit rules for the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls or the lines are commented out, this is a finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
The "-k" allows for specifying an arbitrary identifier and the string after it does not need to match the example output above.)
  desc 'fix', 'Configure the audit system to generate an audit event for any unsuccessful use of the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

Notes: For 32-bit architectures, only the 32-bit specific entries are required. 
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

To reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20982r809521_chk'
  tag severity: 'medium'
  tag gid: 'V-219257'
  tag rid: 'SV-219257r809523_rule'
  tag stig_id: 'UBTU-18-010334'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-20981r809522_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000474-GPOS-00219']
  tag 'documentable'
  tag legacy: ['V-100739', 'SV-109843']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
