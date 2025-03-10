control 'SV-216254' do
  title 'Audit records must include when (date and time) the events occurred.'
  desc 'Without accurate time stamps malicious activity cannot be accurately tracked.'
  desc 'check', 'The Audit Configuration profile is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Check the status of the audit system. It must be auditing.

# pfexec auditconfig -getcond

If this command does not report:

audit condition = auditing

this is a finding.'
  desc 'fix', 'The Audit Control profile is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

If auditing has been disabled, it must be enabled with the following command:

# pfexec audit -s'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17490r370850_chk'
  tag severity: 'medium'
  tag gid: 'V-216254'
  tag rid: 'SV-216254r603267_rule'
  tag stig_id: 'SOL-11.1-010150'
  tag gtitle: 'SRG-OS-000038'
  tag fix_id: 'F-17488r370851_fix'
  tag 'documentable'
  tag legacy: ['V-47797', 'SV-60673']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
