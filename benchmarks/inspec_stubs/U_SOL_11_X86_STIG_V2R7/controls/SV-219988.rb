control 'SV-219988' do
  title 'The audit system must support an audit reduction capability.'
  desc 'Using the audit system will utilize the audit reduction capability. Without an audit reduction capability, users find it difficult to identify specific patterns of attack.'
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
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-21698r372418_chk'
  tag severity: 'medium'
  tag gid: 'V-219988'
  tag rid: 'SV-219988r854551_rule'
  tag stig_id: 'SOL-11.1-010060'
  tag gtitle: 'SRG-OS-000349'
  tag fix_id: 'F-21697r372419_fix'
  tag 'documentable'
  tag legacy: ['V-47783', 'SV-60659']
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
