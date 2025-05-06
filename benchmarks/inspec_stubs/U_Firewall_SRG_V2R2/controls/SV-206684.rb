control 'SV-206684' do
  title 'In the event that communication with the central audit server is lost, the firewall must continue to queue traffic log records locally.'
  desc 'It is critical that when the network element is at risk of failing to process traffic logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.

In accordance with DoD policy, the traffic log must be sent to a central audit server. When logging functions are lost, system processing cannot be shut down because firewall availability is an overriding concern given the role of the firewall in the enterprise. The system should either be configured to log events to an alternative server or queue log records locally. Upon restoration of the connection to the central audit server, action should be taken to synchronize the local log data with the central audit server.

If the central audit server uses User Datagram Protocol (UDP) communications instead of a connection oriented protocol such as TCP, a method for detecting a lost connection must be implemented.'
  desc 'check', 'Verify logging has been enabled and configured for local queuing of the traffic log.

If a local log file (or files) is not configured to capture events locally if communication with the central audit server is lost, this is a finding.'
  desc 'fix', 'Configure local backup events files to capture DoD-defined auditable events either consistently or, if possible, in the event communication with the central audit server is lost.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6941r297831_chk'
  tag severity: 'medium'
  tag gid: 'V-206684'
  tag rid: 'SV-206684r604133_rule'
  tag stig_id: 'SRG-NET-000089-FW-000019'
  tag gtitle: 'SRG-NET-000089'
  tag fix_id: 'F-6941r297832_fix'
  tag 'documentable'
  tag legacy: ['SV-94157', 'V-79451']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
