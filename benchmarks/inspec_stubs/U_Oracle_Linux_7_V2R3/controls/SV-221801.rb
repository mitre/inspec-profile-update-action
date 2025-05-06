control 'SV-221801' do
  title 'The Oracle Linux operating system must generate audit records for all unsuccessful account access events.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify the operating system generates audit records when unsuccessful account access events occur. 

Check the file system rule in "/etc/audit/audit.rules" with the following commands: 

# grep -i /var/run/faillock /etc/audit/audit.rules

-w /var/run/faillock -p wa -k logins

If the command does not return any output, this is a finding.'
  desc 'fix', 'Configure the operating system to generate audit records when unsuccessful account access events occur. 

Add or update the following rule in "/etc/audit/rules.d/audit.rules": 

-w /var/run/faillock -p wa -k logins

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23516r419475_chk'
  tag severity: 'medium'
  tag gid: 'V-221801'
  tag rid: 'SV-221801r603260_rule'
  tag stig_id: 'OL07-00-030610'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-23505r419476_fix'
  tag satisfies: ['SRG-OS-000392-GPOS-00172', 'SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag legacy: ['V-99341', 'SV-108445']
  tag cci: ['CCI-002884', 'CCI-000172']
  tag nist: ['MA-4 (1) (a)', 'AU-12 c']
end
