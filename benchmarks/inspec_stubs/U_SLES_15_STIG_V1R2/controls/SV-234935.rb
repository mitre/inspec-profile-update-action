control 'SV-234935' do
  title 'The SUSE operating system must generate audit records for all uses of the umount system call.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "umount" and "umount2" system calls.

Check that the system calls are being audited by performing the following command:

> sudo auditctl -l | grep 'umount'

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=-1 -k privileged-umount
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=-1 -k privileged-umount
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=-1 -k privileged-umount

If both the "b32" and "b64" audit rules are not defined for the "umount" syscall, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "umount" and "umount2" system calls.

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=4294967295 -k privileged-umount
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-umount
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-umount

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38123r619074_chk'
  tag severity: 'low'
  tag gid: 'V-234935'
  tag rid: 'SV-234935r622137_rule'
  tag stig_id: 'SLES-15-030360'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38086r619075_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-12 c', 'MA-4 (1) (a)']
end
