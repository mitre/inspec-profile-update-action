control 'SV-217240' do
  title 'The SUSE operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation mitigates this risk.

To address access requirements, many SUSE operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Verify the SUSE operating system generates an audit record when all modifications occur to the "/etc/gshadow" file.

Check that the following file is being watched by performing the following command on the system rules in "/etc/audit/audit.rules":

# sudo grep /etc/gshadow /etc/audit/audit.rules

-w /etc/gshadow -p wa -k account_mod

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record when all modifications to the "/etc/gshadow" file occur.

Add or update the following rule to "/etc/audit/rules.d/audit.rules":

-w /etc/gshadow -p wa -k account_mod

The audit daemon must be restarted for any changes to take effect.   

# sudo systemctl restart auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18468r369876_chk'
  tag severity: 'medium'
  tag gid: 'V-217240'
  tag rid: 'SV-217240r603262_rule'
  tag stig_id: 'SLES-12-020590'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-18466r369877_fix'
  tag satisfies: ['SRG-OS-000004-GPOS-00004', 'SRG-OS-000239-GPOS-00089', 'SRG-OS-000240-GPOS-00090', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000476-GPOS-00221']
  tag 'documentable'
  tag legacy: ['V-77393', 'SV-92089']
  tag cci: ['CCI-000172', 'CCI-000018', 'CCI-001403', 'CCI-002130']
  tag nist: ['AU-12 c', 'AC-2 (4)', 'AC-2 (4)', 'AC-2 (4)']
end
