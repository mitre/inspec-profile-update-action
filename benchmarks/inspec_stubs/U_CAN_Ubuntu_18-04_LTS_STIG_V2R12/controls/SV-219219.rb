control 'SV-219219' do
  title 'The Ubuntu operating system must generate audit records for the /var/log/btmp file.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', "Verify the Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/log/btmp file.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep '/var/log/btmp'

-w /var/log/btmp -p wa -k logins

If the command does not return a line matching the example or the line is commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above."
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the /var/log/btmp file.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/log/btmp -p wa -k logins

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20944r304985_chk'
  tag severity: 'medium'
  tag gid: 'V-219219'
  tag rid: 'SV-219219r610963_rule'
  tag stig_id: 'UBTU-18-010240'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-20943r304986_fix'
  tag 'documentable'
  tag legacy: ['SV-109769', 'V-100665']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
