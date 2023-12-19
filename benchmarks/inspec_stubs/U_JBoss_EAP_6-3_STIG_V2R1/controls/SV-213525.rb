control 'SV-213525' do
  title 'JBoss application and management ports must be approved by the PPSM CAL.'
  desc 'Some networking protocols may not meet organizational security requirements to protect data and components.

Application servers natively host a number of various features, such as management interfaces, httpd servers and message queues. These features all run on TCPIP ports. This creates the potential that the vendor may choose to utilize port numbers or network services that have been deemed unusable by the organization. The application server must have the capability to both reconfigure and disable the assigned ports without adversely impacting application server operation capabilities. For a list of approved ports and protocols, reference the DoD ports and protocols website at https://powhatan.iiie.disa.mil/ports/cal.html.'
  desc 'check', 'Open the EAP web console by pointing a web browser to HTTPS://<Servername>:9443 or HTTP://<Servername>:9990

Log on to the admin console using admin credentials
Select the "Configuration" tab
Expand the "General Configuration" sub system by clicking on the +
Select "Socket Binding"
Select the "View" option next to "standard-sockets"
Select "Inbound"

Review the configured ports and determine if they are all approved by the PPSM CAL.

If all the ports are not approved by the PPSM CAL, this is a finding.'
  desc 'fix', 'Open the EAP web console by pointing a web browser to HTTPS://<Servername>:9990

Log on to the admin console using admin credentials
Select the "Configuration" tab
Expand the "General Configuration" sub system by clicking on the +
Select "Socket Binding"
Select the "View" option next to "standard-sockets"
Select "Inbound"

Select the port that needs to be reconfigured and select "Edit".'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14748r296241_chk'
  tag severity: 'medium'
  tag gid: 'V-213525'
  tag rid: 'SV-213525r615939_rule'
  tag stig_id: 'JBOS-AS-000255'
  tag gtitle: 'SRG-APP-000142-AS-000014'
  tag fix_id: 'F-14746r296242_fix'
  tag 'documentable'
  tag legacy: ['SV-76765', 'V-62275']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
