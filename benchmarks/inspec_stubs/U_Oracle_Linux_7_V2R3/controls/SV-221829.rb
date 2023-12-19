control 'SV-221829' do
  title 'The Oracle Linux operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

# grep /etc/security/opasswd /etc/audit/audit.rules

-w /etc/security/opasswd -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.

Add or update the following file system rule in "/etc/audit/rules.d/audit.rules":

-w /etc/security/opasswd -p wa -k identity

The audit daemon must be restarted for the changes to take effect:
# systemctl restart auditd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23544r419559_chk'
  tag severity: 'medium'
  tag gid: 'V-221829'
  tag rid: 'SV-221829r603260_rule'
  tag stig_id: 'OL07-00-030874'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-23533r419560_fix'
  tag 'documentable'
  tag legacy: ['SV-108501', 'V-99397']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
