control 'SV-217213' do
  title 'The SUSE operating system must generate audit records for all uses of the mount command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "mount" command.

Check that the following command call is being audited by performing the following command on the system rules in "/etc/audit/audit.rules":

# sudo grep -iw mount /etc/audit/audit.rules

-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount

If both the "b32" and "b64" audit rules are not defined for the "mount" syscall, this is a finding.

If all uses of the "mount" command are not being audited, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses the "mount" command.

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount
-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount

The audit daemon must be restarted for any changes to take effect. 

# sudo systemctl restart auditd.service'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18441r369795_chk'
  tag severity: 'low'
  tag gid: 'V-217213'
  tag rid: 'SV-217213r603262_rule'
  tag stig_id: 'SLES-12-020290'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18439r369796_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-77333', 'SV-92029']
  tag cci: ['CCI-000172', 'CCI-000169', 'CCI-000130', 'CCI-002884']
  tag nist: ['AU-12 c', 'AU-12 a', 'AU-3 a', 'MA-4 (1) (a)']
end
