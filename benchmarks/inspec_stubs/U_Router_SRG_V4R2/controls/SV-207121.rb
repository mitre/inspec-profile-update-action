control 'SV-207121' do
  title 'The router must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, security personnel need to know the source of the event.

In addition to logging where events occur within the network, the audit records must also identify sources of events such as IP addresses, processes, and node or device names.'
  desc 'check', 'The router must log all packets that have been dropped via the access control list.

If the router fails to log all packets that have been dropped via the control list, this is a finding.

Log output must contain the source IP address and port of the filtered packets.

If the logged output does not contain source IP address and port of the filtered packets, this is a finding.'
  desc 'fix', 'Configure the router to record the source address in the log record for packets being dropped.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7382r382256_chk'
  tag severity: 'medium'
  tag gid: 'V-207121'
  tag rid: 'SV-207121r604135_rule'
  tag stig_id: 'SRG-NET-000077-RTR-000001'
  tag gtitle: 'SRG-NET-000077'
  tag fix_id: 'F-7382r382257_fix'
  tag 'documentable'
  tag legacy: ['V-78233', 'SV-92939']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
