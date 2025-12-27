control 'SV-216256' do
  title 'Audit records must include the sources of the events that occurred.'
  desc 'Without accurate source information malicious activity cannot be accurately tracked.'
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
  tag check_id: 'C-17492r370856_chk'
  tag severity: 'medium'
  tag gid: 'V-216256'
  tag rid: 'SV-216256r603267_rule'
  tag stig_id: 'SOL-11.1-010170'
  tag gtitle: 'SRG-OS-000040'
  tag fix_id: 'F-17490r370857_fix'
  tag 'documentable'
  tag legacy: ['V-47801', 'SV-60677']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
