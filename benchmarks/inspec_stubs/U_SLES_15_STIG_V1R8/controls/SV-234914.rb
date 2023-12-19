control 'SV-234914' do
  title 'The SUSE operating system must generate audit records for all uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary, since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls.

Check that the system calls are being audited by performing the following command:

> sudo auditctl -l | grep 'open\|truncate\|creat'

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access

If both the "b32" and "b64" audit rules are not defined for the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" syscalls, this is a finding.

If the output does not produce rules containing "-F exit=-EPERM", this is a finding.

If the output does not produce rules containing "-F exit=-EACCES", this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "creat", "open", "openat", "open_by_handle_at", "truncate", and "ftruncate" system calls. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access

-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

To reload the rules file, restart the audit daemon:

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38102r809461_chk'
  tag severity: 'medium'
  tag gid: 'V-234914'
  tag rid: 'SV-234914r854232_rule'
  tag stig_id: 'SLES-15-030150'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38065r854231_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000461-GPOS-00205', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
