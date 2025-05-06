control 'SV-217231' do
  title 'The SUSE operating system must generate audit records for all uses of the truncate command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "truncate" command.

Check that the following command call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

# sudo grep -i truncate /etc/audit/audit.rules

-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access

-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

If both the "b32" and "b64" audit rules are not defined for the "truncate" syscall, this is a finding.

If the output does not produce rules containing "-F exit=-EPERM", this is a finding.

If the output does not produce rules containing "-F exit=-EACCES", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "truncate" command. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":


-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access

-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18459r369849_chk'
  tag severity: 'medium'
  tag gid: 'V-217231'
  tag rid: 'SV-217231r603262_rule'
  tag stig_id: 'SLES-12-020500'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-18457r369850_fix'
  tag satisfies: ['SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203']
  tag 'documentable'
  tag legacy: ['SV-92071', 'V-77375']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
