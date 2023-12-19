control 'SV-242598' do
  title 'The Cisco ISE must continue to queue traffic log records locally when communication with the central log server is lost and there is an audit archival failure.'
  desc 'It is critical that when the network element is at risk of failing to process traffic logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode.

In accordance with DoD policy, the traffic log must be sent to a central audit server. When logging functions are lost, system processing cannot be shut down because NAC availability is an overriding concern given the role of the firewall in the enterprise. The system should either be configured to log events to an alternative server or queue log records locally. Upon restoration of the connection to the central log server, action should be taken to synchronize the local log data with the central audit server.

If the central audit server uses User Datagram Protocol (UDP) communications instead of a connection-oriented protocol such as TCP, a method for detecting a lost connection must be implemented.'
  desc 'check', 'Verify that logging targets are configured to buffer syslog messages when the server is down. 

From the Web Admin portal: 
1. Choose Administration >> System >> Logging >> Remote Logging Targets.
2. Select remote targets and verify that "Buffer Messages When Server Down" box is checked.

Note: If "LogCollector" and "LogCollector2" are configured for UDP and ISE Messaging service is configured, this is not a finding. 

Verify that ISE Messaging Service is enabled.

From the Web Admin portal: 
1. Choose Administration >> System >> Logging >> Log Settings.
2. Verify that "Use ISE Messaging Service for UDP Syslogs delivery to MnT" box is checked.

If messages are not buffered for remote syslog servers, this is a finding.'
  desc 'fix', 'Configure the logging targets to buffer syslog messages when the server is down.

Navigate to Administration >> System >> Logging >> Remote Logging Targets.

1. Select "Secure Syslog" or "TCP Syslog" in the Target Type drop-down menu.
2. Configure a desired name.
3. Configure the Host/IP address.
4. Check the box for "Buffer Messages When Server Down".
5. If "Secure Syslog" is used, select a CA certificate to use to define what system certificate to use to secure this connection.
6. Choose "Submit".

And/or:

Enable ISE Messaging Service.  

From the Web Admin portal: 
1. Choose Administration >> System >> Logging >> Log Settings.
2. Check "Use "ISE Messaging Service" for UDP Syslogs delivery to MnT".
3. Choose "Save".

Note: ISE Messaging Service will encrypt and buffer messages destined to the Monitoring (MnT) nodes. The logging targets of "LogCollector" and "LogCollector2" are the primary and secondary MnT nodes respectively.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45873r714102_chk'
  tag severity: 'medium'
  tag gid: 'V-242598'
  tag rid: 'SV-242598r714104_rule'
  tag stig_id: 'CSCO-NC-000240'
  tag gtitle: 'SRG-NET-000089-NAC-000450'
  tag fix_id: 'F-45830r714103_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
