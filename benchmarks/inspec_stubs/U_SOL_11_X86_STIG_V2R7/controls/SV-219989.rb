control 'SV-219989' do
  title 'The audit system records must be able to be used by a report generation capability.'
  desc 'Enabling the audit system will produce records for use in report generation.  Without an audit reporting capability, users find it difficult to identify specific patterns of attack.'
  desc 'check', 'The Audit Configuration profile is required.

This check applies to the global zone only.  Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Check the status of the audit system. It must be auditing.

# pfexec auditconfig -getcond

If this command does not report:

audit condition = auditing

this is a finding.'
  desc 'fix', 'The Audit Control profile is required.

This action applies to the global zone only.  Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

If auditing has been disabled, it must be enabled with the following command:

# pfexec audit -s'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21699r372421_chk'
  tag severity: 'medium'
  tag gid: 'V-219989'
  tag rid: 'SV-219989r854552_rule'
  tag stig_id: 'SOL-11.1-010070'
  tag gtitle: 'SRG-OS-000352'
  tag fix_id: 'F-21698r372422_fix'
  tag 'documentable'
  tag legacy: ['V-47785', 'SV-60661']
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
