control 'SV-239947' do
  title 'The Cisco ASA must be configured to queue log records locally in the event that the central audit server is down or not reachable.'
  desc 'If the system were to continue processing after audit failure, actions can be taken on the system that cannot be tracked and recorded for later forensic analysis.

Because of the importance of ensuring mission/business continuity, organizations may determine that the nature of the audit failure is not so severe that it warrants a complete shutdown of the application supporting the core organizational missions/business operations. In those instances, partial application shutdowns or operating in a degraded mode with reduced capability may be viable alternatives.

This requirement only applies to components where this is specific to the function of the device (e.g., IDPS sensor logs, firewall logs). This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'If the ASA is configured to send syslog messages to a TCP-based syslog server, and if the syslog server is down new connections are blocked. To continue to allow new connections and queue log records verify that the logging permit-hostdown and the queue size has been increased (default is 512).

logging enable
…
…
…
logging queue 8192
logging host NDM_INTERFACE 10.1.22.2 6/1514
logging permit-hostdown

If the ASA is not configured to queue log records locally in the event that the central audit server is down or not reachable, this is a finding.'
  desc 'fix', 'To continue to allow new connections and queue log records in the event the syslog server is not reachable, configure logging permit-hostdown and increase the queue size.

ASA(config)# logging permit-hostdown 
ASA(config)# logging queue 8192'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43180r666245_chk'
  tag severity: 'medium'
  tag gid: 'V-239947'
  tag rid: 'SV-239947r856162_rule'
  tag stig_id: 'CASA-VN-000080'
  tag gtitle: 'SRG-NET-000336-VPN-001280'
  tag fix_id: 'F-43139r666246_fix'
  tag 'documentable'
  tag cci: ['CCI-001861']
  tag nist: ['AU-5 (4)']
end
