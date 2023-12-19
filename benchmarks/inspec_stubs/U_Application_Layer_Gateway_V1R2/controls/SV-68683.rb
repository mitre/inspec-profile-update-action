control 'SV-68683' do
  title 'The ALG must provide an immediate real-time alert to, at a minimum, the SCA and ISSO, of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  desc 'Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG provides an immediate real-time alert to, at a minimum, the SCA and ISSO of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.

If the ALG does not provide an immediate real-time alert to, at a minimum, the SCA and ISSO, of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server, this is a finding.'
  desc 'fix', 'Configure the ALG to provide an immediate real-time alert to, at a minimum, the SCA and ISSO of all audit failure events where the detection and/or prevention function is unable to write events to either local storage or the centralized server.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55053r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54437'
  tag rid: 'SV-68683r1_rule'
  tag stig_id: 'SRG-NET-000335-ALG-000053'
  tag gtitle: 'SRG-NET-000335-ALG-000053'
  tag fix_id: 'F-59291r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
