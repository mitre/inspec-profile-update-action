control 'SV-217219' do
  title 'The SUSE operating system must generate audit records for all uses of the fsetxattr command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "fsetxattr" command.

Check that the following command call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

# sudo grep -i fsetxattr /etc/audit/audit.rules

-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the "fsetxattr" syscall, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "fsetxattr" command. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18447r369813_chk'
  tag severity: 'medium'
  tag gid: 'V-217219'
  tag rid: 'SV-217219r603262_rule'
  tag stig_id: 'SLES-12-020380'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18445r369814_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-92047', 'V-77351']
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
