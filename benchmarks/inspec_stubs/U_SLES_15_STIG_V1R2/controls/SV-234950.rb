control 'SV-234950' do
  title 'The SUSE operating system must generate audit records for all uses of the pam_timestamp_check command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for any use of the "pam_timestamp_check" command.

Check that the command is being audited by performing the following command:

> sudo auditctl -l | grep -w '/sbin/pam_timestamp_check'

-a always,exit -S all -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-pam_timestamp_check

If the command does not return any output, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "pam_timestamp_check" command. 

Add or update the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38138r619119_chk'
  tag severity: 'medium'
  tag gid: 'V-234950'
  tag rid: 'SV-234950r622137_rule'
  tag stig_id: 'SLES-15-030510'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38101r619120_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-000130', 'CCI-000169', 'CCI-002884']
  tag nist: ['AU-12 c', 'AU-3 a', 'AU-12 a', 'MA-4 (1) (a)']
end
