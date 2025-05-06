control 'SV-234907' do
  title 'The SUSE operating system must generate audit records for all uses of the gpasswd command.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "gpasswd" command.

Check that the command is being audited by performing the following command:

> sudo auditctl -l | grep -w '/usr/bin/gpasswd'

-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-gpasswd

If the command does not return any output, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "gpasswd" command.

Add or update the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.3
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38095r618990_chk'
  tag severity: 'low'
  tag gid: 'V-234907'
  tag rid: 'SV-234907r854224_rule'
  tag stig_id: 'SLES-15-030080'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-38058r618991_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000169', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-3 a', 'AU-12 a', 'AU-12 c', 'MA-4 (1) (a)']
end
