control 'SV-239857' do
  title 'The Cisco ASA must be configured to queue log records locally in the event that the central audit server is down or not reachable.'
  desc 'It is critical that when the network element is at risk of failing to process traffic logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.

In accordance with DoD policy, the traffic log must be sent to a central audit server. When logging functions are lost, system processing cannot be shut down because firewall availability is an overriding concern given the role of the firewall in the enterprise. The system should either be configured to log events to an alternative server or queue log records locally. Upon restoration of the connection to the central audit server, action should be taken to synchronize the local log data with the central audit server.

If the central audit server uses User Datagram Protocol (UDP) communications instead of a connection oriented protocol such as TCP, a method for detecting a lost connection must be implemented.'
  desc 'check', 'Review the ASA configuration and verify that logging to the buffer is enabled and that the queue size has been increased as shown in the example below.

logging enable
logging buffered informational
logging queue 8192
logging host NDM_INTERFACE 10.1.22.2 6/1514

Note: Configuring a value of 0 for the queue size will set it to maximum size for the specific platform.

If the ASA is not configured to queue log records locally In the event that the central audit server is down or not reachable, this is a finding.'
  desc 'fix', 'To continue to allow new connections and queue log records in the event the syslog server is not reachable, configure logging buffered and increase the queue size as shown in the example below.

ASA(config)# logging buffered informational
ASA(config)# logging queue 8192'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43090r665855_chk'
  tag severity: 'medium'
  tag gid: 'V-239857'
  tag rid: 'SV-239857r665857_rule'
  tag stig_id: 'CASA-FW-000090'
  tag gtitle: 'SRG-NET-000089-FW-000019'
  tag fix_id: 'F-43049r665856_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
