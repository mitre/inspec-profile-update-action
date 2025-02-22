control 'SV-217242' do
  title 'The SUSE operating system must generate audit records for all uses of the setfacl command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "setfacl" command.

Check that the following command call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

# sudo grep -i setfacl /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k prim_mod

If the command does not return any output or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "setfacl" command. 

Add or update the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k prim_mod

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18470r622388_chk'
  tag severity: 'medium'
  tag gid: 'V-217242'
  tag rid: 'SV-217242r603926_rule'
  tag stig_id: 'SLES-12-020610'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18468r622389_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-77397', 'SV-92093']
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
