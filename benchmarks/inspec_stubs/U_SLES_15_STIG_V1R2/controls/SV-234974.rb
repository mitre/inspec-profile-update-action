control 'SV-234974' do
  title 'The SUSE operating system must generate audit records for all uses of the unlinkat system call.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "unlinkat" system call.

Check that the system call is being audited by performing the following command:

> sudo auditctl -l | grep -w 'unlinkat'

-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=-1 -k perm_mod

If the command does not return lines that match the example, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "unlinkat" system call.

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k perm_mod

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38162r619191_chk'
  tag severity: 'medium'
  tag gid: 'V-234974'
  tag rid: 'SV-234974r622137_rule'
  tag stig_id: 'SLES-15-030750'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-38125r619192_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
