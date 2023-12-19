control 'SV-216249' do
  title 'The operating system must provide the capability to automatically process audit records for events of interest based upon selectable, event criteria.'
  desc 'Without an audit reporting capability, users find it difficult to identify specific patterns of attack.'
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
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17485r370835_chk'
  tag severity: 'medium'
  tag gid: 'V-216249'
  tag rid: 'SV-216249r603267_rule'
  tag stig_id: 'SOL-11.1-010080'
  tag gtitle: 'SRG-OS-000054'
  tag fix_id: 'F-17483r370836_fix'
  tag 'documentable'
  tag legacy: ['SV-60663', 'V-47787']
  tag cci: ['CCI-000158']
  tag nist: ['AU-7 (1)']
end
