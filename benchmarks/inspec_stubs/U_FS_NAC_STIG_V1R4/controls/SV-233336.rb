control 'SV-233336' do
  title 'Forescout must be configured with a secondary log server, in case the primary log is unreachable. This is required for compliance with C2C Step 1.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. This requirement pertains to NAC types and threat protection events of events as opposed to device management events vs. operating system and system log types of events in the NDM check.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Verify the NAC is configured with a secondary log server in case the primary log is unreachable.

1. Log on to the Forescout UI.
2. Select Tools >> Options >>Syslog >>Syslog Triggers.
3. Verify all boxes in the NAC Events section are checked. This includes the "Include NAC policy logs" and the "Include NAC policy match/unmatch events".

If the NAC is not configured with a secondary log server in case the primary log is unreachable, this is a finding.'
  desc 'fix', '1. Log on to the Forescout UI.
2. Select Tools >> Options >> Syslog >> Syslog Triggers.
3. Check all boxes in the NAC Events section. This includes the "Include NAC policy logs" and the "Include NAC policy match/unmatch events".'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36531r811421_chk'
  tag severity: 'medium'
  tag gid: 'V-233336'
  tag rid: 'SV-233336r856517_rule'
  tag stig_id: 'FORE-NC-000420'
  tag gtitle: 'SRG-NET-000336-NAC-001390'
  tag fix_id: 'F-36496r811422_fix'
  tag 'documentable'
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
