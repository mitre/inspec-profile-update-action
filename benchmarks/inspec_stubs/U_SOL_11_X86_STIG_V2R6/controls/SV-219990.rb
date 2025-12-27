control 'SV-219990' do
  title 'The operating system must support the capability to compile audit records from multiple components within the system into a system-wide (logical or physical) audit trail that is time-correlated to within organization-defined level of tolerance.'
  desc 'Without auditing, individual system accesses cannot be tracked, and malicious activity cannot be detected and traced back to an individual account.

Without accurate time stamps, source, user, and activity information, malicious activity cannot be accurately tracked.

Without an audit reduction and reporting capability, users find it difficult to identify specific patterns of attack.'
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
  tag check_id: 'C-21700r372433_chk'
  tag severity: 'medium'
  tag gid: 'V-219990'
  tag rid: 'SV-219990r603268_rule'
  tag stig_id: 'SOL-11.1-010130'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-21699r372434_fix'
  tag 'documentable'
  tag legacy: ['SV-60669', 'V-47793']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
