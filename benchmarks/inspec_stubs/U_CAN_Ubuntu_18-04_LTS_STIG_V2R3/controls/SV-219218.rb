control 'SV-219218' do
  title 'The Ubuntu operating system must generate audit records for the /var/run/wtmp file.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', "Verify the Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/run/wtmp file.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep '/var/run/wtmp'

-w /var/run/wtmp -p wa -k logins

If the command does not return a line matching the example or the line is commented out, this is a finding.

Note: The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above."
  desc 'fix', 'Configure the audit system to generate audit events showing start and stop times for user access via the /var/run/wtmp file.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-w /var/run/wtmp -p wa -k logins

Note:
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20943r304982_chk'
  tag severity: 'medium'
  tag gid: 'V-219218'
  tag rid: 'SV-219218r610963_rule'
  tag stig_id: 'UBTU-18-010239'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-20942r304983_fix'
  tag 'documentable'
  tag legacy: ['V-100663', 'SV-109767']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
