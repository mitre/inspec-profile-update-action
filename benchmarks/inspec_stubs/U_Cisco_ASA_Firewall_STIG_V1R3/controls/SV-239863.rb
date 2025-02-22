control 'SV-239863' do
  title 'The Cisco ASA must be configured to generate a real-time alert to organization-defined personnel and/or the firewall administrator in the event communication with the central audit server is lost.'
  desc 'Without a real-time alert (less than a second), security personnel may be unaware of an impending failure of the audit functions and system operation may be adversely impacted. Alerts provide organizations with urgent messages. Automated alerts can be conveyed in a variety of ways, including via a regularly monitored console, telephonically, via electronic mail, via text message, or via websites.

Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. Most firewalls use UDP to send audit records to the server and cannot tell if the server has received the transmission, thus the site should either implement a connection-oriented communications solution (e.g., TCP) or implement a heartbeat with the central audit server and send an alert if it is unreachable. The ISSM or ISSO may designate the firewall/system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, and then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Review the ASA configuration to determine if it will send an email alert to organization-defined personnel and/or the firewall administrator if  communication with the central audit server is lost as shown in the example below.

logging enable
logging host NDM_INTERFACE 10.1.22.2 6/1514
logging permit-hostdown
logging mail errors
logging from-address firewall@mail.mil
logging recipient-address OurFWadmin@mail.mil level errors
logging recipient-address OurISSO@mail.mil level errors
…
…
…
smtp-server 10.1.12.33

Note: Severity level must be set at 3 (errors) or higher as the following message is seen when an ASA loses communication with the syslog server: %ASA-3-201008 or %ASA-3-414003: Disallowing new connections.

If the ASA is not configured to generate a real-time alert to organization-defined personnel and/or the firewall administrator if communication with the central audit server is lost, this is a finding.'
  desc 'fix', 'Configure the ASA to send an email alert to the organization-defined personnel and/or firewall administrator for syslog messages at severity level 3.

ASA(config)# logging mail 3 
ASA(config)# logging recipient-address OurFWadmin@mail.mil
ASA(config)# logging recipient-address OurISSO@mail.mil
ASA(config)# logging from-address firewall@mail.mil
ASA(config)# smtp-server 10.1.12.33
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43096r665873_chk'
  tag severity: 'medium'
  tag gid: 'V-239863'
  tag rid: 'SV-239863r855805_rule'
  tag stig_id: 'CASA-FW-000210'
  tag gtitle: 'SRG-NET-000335-FW-000017'
  tag fix_id: 'F-43055r665874_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
