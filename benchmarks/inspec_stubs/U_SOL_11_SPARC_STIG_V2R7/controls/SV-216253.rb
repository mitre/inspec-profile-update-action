control 'SV-216253' do
  title 'Audit records must include what type of events occurred.'
  desc 'Without proper system auditing, individual system accesses cannot be tracked, and malicious activity cannot be detected and traced back to an individual account.'
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
  tag check_id: 'C-17489r370847_chk'
  tag severity: 'medium'
  tag gid: 'V-216253'
  tag rid: 'SV-216253r603267_rule'
  tag stig_id: 'SOL-11.1-010140'
  tag gtitle: 'SRG-OS-000037'
  tag fix_id: 'F-17487r370848_fix'
  tag 'documentable'
  tag legacy: ['V-47795', 'SV-60671']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
