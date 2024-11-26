control 'SV-217237' do
  title 'The SUSE operating system must generate audit records for all uses of the gpasswd command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "gpasswd" command.

Check that the following command call is being audited by performing the following command on the system rules in "/etc/audit/audit.rules":

# sudo grep -i gpasswd /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd

If the command does not return any output or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses the "gpasswd" command.

Add or update the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18465r622376_chk'
  tag severity: 'low'
  tag gid: 'V-217237'
  tag rid: 'SV-217237r603914_rule'
  tag stig_id: 'SLES-12-020560'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18463r622377_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-77387', 'SV-92083']
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
