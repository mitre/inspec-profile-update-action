control 'SV-234960' do
  title 'The SUSE operating system must generate audit records for all uses of the truncate command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "truncate" system call.

Check that the system call is being audited by performing the following command:

> sudo auditctl -l | grep -w 'truncate'

-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k perm_access

-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k perm_access

If both the "b32" and "b64" audit rules are not defined for the "truncate" syscall, this is a finding.

If the output does not produce rules containing "-F exit=-EPERM", this is a finding.

If the output does not produce rules containing "-F exit=-EACCES", this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "truncate" system call. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access

-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38148r619149_chk'
  tag severity: 'medium'
  tag gid: 'V-234960'
  tag rid: 'SV-234960r622137_rule'
  tag stig_id: 'SLES-15-030610'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-38111r619150_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
