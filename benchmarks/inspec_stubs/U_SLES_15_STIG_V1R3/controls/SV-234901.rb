control 'SV-234901' do
  title 'The SUSE operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation mitigates this risk.

To address access requirements, many SUSE operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', %q(Verify the SUSE operating system generates an audit record when modifications occur to the "/etc/shadow" file.

Check that the file is being audited by performing the following command:

> sudo auditctl -l | grep -w '/etc/shadow'

-w /etc/shadow -p wa -k account_mod

If the command does not return a line, this is a finding.

Notes:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record when all modifications to the "/etc/shadow" file occur.

Add or update the following rule to "/etc/audit/rules.d/audit.rules":

-w /etc/shadow -p wa -k account_mod

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38089r618972_chk'
  tag severity: 'medium'
  tag gid: 'V-234901'
  tag rid: 'SV-234901r622137_rule'
  tag stig_id: 'SLES-15-030020'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-38052r618973_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-002130', 'CCI-002132']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
