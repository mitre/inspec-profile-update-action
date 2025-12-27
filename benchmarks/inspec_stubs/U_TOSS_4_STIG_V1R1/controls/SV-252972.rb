control 'SV-252972' do
  title 'TOSS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing account modification actions provides logging that can be used for forensic purposes. 

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Verify TOSS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow."

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/shadow /etc/audit/audit.rules
-w /etc/shadow -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'
  desc 'fix', 'Configure TOSS to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow."

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/shadow -p wa -k identity

The audit daemon must be restarted for the changes to take effect.

Note: The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56425r824238_chk'
  tag severity: 'medium'
  tag gid: 'V-252972'
  tag rid: 'SV-252972r824240_rule'
  tag stig_id: 'TOSS-04-030000'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-56375r824239_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000466-GPOS-00210', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000172', 'CCI-001403', 'CCI-001404', 'CCI-001405', 'CCI-002130']
  tag nist: ['AC-2 (4)', 'AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
