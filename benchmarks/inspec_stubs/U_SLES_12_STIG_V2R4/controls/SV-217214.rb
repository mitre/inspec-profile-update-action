control 'SV-217214' do
  title 'The SUSE operating system must generate audit records for all uses of the umount command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "umount" command.

Check that the following command call is being audited by performing the following command on the system rules in "/etc/audit/audit.rules":

# sudo grep -iw umount /etc/audit/audit.rules

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=4294967295 -k privileged-umount
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-umount
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-umount

If both the "b32" and "b64" audit rules are not defined for the "umount" syscall, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses the "umount" command.

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S umount -F auid>=1000 -F auid!=4294967295 -k privileged-umount
-a always,exit -F arch=b32 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-umount
-a always,exit -F arch=b64 -S umount2 -F auid>=1000 -F auid!=4294967295 -k privileged-umount

The audit daemon must be restarted for any changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18442r369798_chk'
  tag severity: 'low'
  tag gid: 'V-217214'
  tag rid: 'SV-217214r603262_rule'
  tag stig_id: 'SLES-12-020300'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18440r369799_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['SV-92031', 'V-77335']
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
