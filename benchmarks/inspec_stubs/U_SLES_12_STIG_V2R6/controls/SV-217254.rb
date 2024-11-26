control 'SV-217254' do
  title 'The SUSE operating system must generate audit records for all uses of the delete_module command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the SUSE operating system generates an audit record for all uses of the "delete_module" command.

Check that the following command call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

# sudo grep -i delete_module /etc/audit/audit.rules

-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k unload_module
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k unload_module

If both the "b32" and "b64" audit rules are not defined for the "unload_module" syscall, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "delete_module" command. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k unload_module
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k unload_module

The audit daemon must be restarted for the changes to take effect.

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18482r369918_chk'
  tag severity: 'medium'
  tag gid: 'V-217254'
  tag rid: 'SV-217254r603262_rule'
  tag stig_id: 'SLES-12-020730'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18480r369919_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag legacy: ['V-77421', 'SV-92117']
  tag cci: ['CCI-000169', 'CCI-000172', 'CCI-000130', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-12 c', 'AU-3 a', 'MA-4 (1) (a)']
end
