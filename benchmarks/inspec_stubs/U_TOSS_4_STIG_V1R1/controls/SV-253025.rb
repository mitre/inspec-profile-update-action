control 'SV-253025' do
  title 'TOSS must generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable a new or disabled account. Auditing account modification actions provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify TOSS generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/gshadow /etc/audit/audit.rules

-w /etc/gshadow -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/gshadow -p wa -k identity

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56478r824745_chk'
  tag severity: 'medium'
  tag gid: 'V-253025'
  tag rid: 'SV-253025r824747_rule'
  tag stig_id: 'TOSS-04-030800'
  tag gtitle: 'SRG-OS-000303-GPOS-00120'
  tag fix_id: 'F-56428r824746_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
