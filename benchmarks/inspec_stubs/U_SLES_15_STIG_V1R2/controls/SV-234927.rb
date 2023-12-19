control 'SV-234927' do
  title 'The SUSE operating system must generate audit records for all uses of the fchownat system call.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "fchownat" system call.

Check that the system call is being audited by performing the following command:

> sudo auditctl -l | grep -w 'fchownat'

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the "fchownat" syscall, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "fchownat" system call. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38115r619050_chk'
  tag severity: 'medium'
  tag gid: 'V-234927'
  tag rid: 'SV-234927r622137_rule'
  tag stig_id: 'SLES-15-030280'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38078r619051_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000172', 'CCI-000169', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 c', 'AU-12 a', 'MA-4 (1) (a)']
end
