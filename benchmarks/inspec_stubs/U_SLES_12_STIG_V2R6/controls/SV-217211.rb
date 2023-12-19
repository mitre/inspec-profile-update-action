control 'SV-217211' do
  title 'The SUSE operating system must generate audit records for all uses of the sudo command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for any use of the "sudo" command.

Check that the following command call is being audited by performing the following command on the system rules in "/etc/audit/audit.rules":

# sudo grep -iw sudo /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-sudo

If the command does not return any output or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "sudo" command.

Add or update the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-sudo

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18439r622361_chk'
  tag severity: 'low'
  tag gid: 'V-217211'
  tag rid: 'SV-217211r603899_rule'
  tag stig_id: 'SLES-12-020260'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18437r622362_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-77327', 'SV-92023']
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-12 c', 'MA-4 (1) (a)']
end
