control 'SV-246935' do
  title 'ONTAP must generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Use "cluster log-forwarding show" to see if a remote syslog destination is defined for ONTAP.

If ONTAP does not generate an immediate real-time alert of all audit failure events requiring real-time alerts, this is a finding.'
  desc 'fix', 'If no remote syslog servers are defined, use "cluster log-forwarding create" to define a syslog destination.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50367r769135_chk'
  tag severity: 'medium'
  tag gid: 'V-246935'
  tag rid: 'SV-246935r769137_rule'
  tag stig_id: 'NAOT-AU-000003'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-50321r769136_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
