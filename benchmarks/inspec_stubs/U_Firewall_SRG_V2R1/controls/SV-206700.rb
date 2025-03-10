control 'SV-206700' do
  title 'If communication with the central audit server is lost, the firewall must generate a real-time alert to, at a minimum, the SCA and ISSO.'
  desc 'Without a real-time alert (less than a second), security personnel may be unaware of an impending failure of the audit functions and system operation may be adversely impacted. Alerts provide organizations with urgent messages. Automated alerts can be conveyed in a variety of ways, including via a regularly monitored console, telephonically, via electronic mail, via text message, or via websites.

Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. Most firewalls use UDP to send audit records to the server and cannot tell if the server has received the transmission, thus the site should either implement a connection-oriented communications solution (e.g., TCP) or implement a heartbeat with the central audit server and send an alert if it is unreachable.'
  desc 'check', 'If a network device such as the events, network management, or SNMP server is configured to send an alert when communication is lost with the central audit server, this is not a finding.

Verify the firewall is configured to send an alert via instant message, email, SNMP, or another authorized method to the SCA, ISSO, and other identified personnel when communication is lost with the central audit server.

If the firewall is not configured to send an immediate alert via an approved method when communication is lost with the central audit server, this is a finding.'
  desc 'fix', 'Configure the firewall (or another network device) to send an alert via instant message, email, or another authorized method to the SCA, ISSO, and other identified personnel for any log failure event where the filtering functions are unable to write events to the central audit server.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6957r297879_chk'
  tag severity: 'medium'
  tag gid: 'V-206700'
  tag rid: 'SV-206700r604133_rule'
  tag stig_id: 'SRG-NET-000335-FW-000017'
  tag gtitle: 'SRG-NET-000335'
  tag fix_id: 'F-6957r297880_fix'
  tag 'documentable'
  tag legacy: ['SV-94153', 'V-79447']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
