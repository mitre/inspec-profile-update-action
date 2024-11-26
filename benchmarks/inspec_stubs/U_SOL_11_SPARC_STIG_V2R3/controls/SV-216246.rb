control 'SV-216246' do
  title 'The audit system must produce records containing sufficient information to establish the identity of any user/subject associated with the event.'
  desc 'Enabling the audit system will produce records with accurate time stamps, source, user, and activity information. Without this information malicious activity cannot be accurately tracked.'
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
  tag check_id: 'C-17482r370826_chk'
  tag severity: 'medium'
  tag gid: 'V-216246'
  tag rid: 'SV-216246r603267_rule'
  tag stig_id: 'SOL-11.1-010040'
  tag gtitle: 'SRG-OS-000255'
  tag fix_id: 'F-17480r370827_fix'
  tag 'documentable'
  tag legacy: ['V-47781', 'SV-60657']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
