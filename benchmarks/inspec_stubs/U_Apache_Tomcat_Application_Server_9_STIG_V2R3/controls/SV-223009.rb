control 'SV-223009' do
  title 'Connector address attribute must be set.'
  desc 'Connectors are how Tomcat receives requests over a network port, passes them to hosted web applications via HTTP or AJP, and then sends back the results to the requestor. The "address" attribute specifies which network interface the connector listens on. If no IP address is specified, the connector will listen on all configured interfaces. Access to the connector must be restricted to only the network interface(s) specified in the System Security Plan (SSP).'
  desc 'check', 'Review SSP documentation for list of approved connectors and associated TCP/IP ports and interfaces.

Verify the address attribute is specified for each connector and is set to the network interface specified in the SSP.

Execute the following command to find configured Connectors:

sudo grep -i -B1 -A5 connector $CATALINA_BASE/conf/server.xml

Review results and examine the "address=" field for each connector.

If the connector address attribute is not specified as per the SSP, this is a finding.'
  desc 'fix', 'Ensure the address attribute for each connector and the network interfaces are specified in the SSP.

Edit the following file From the Tomcat server as a privileged user:

$CATALINA_BASE/conf/server.xml

Locate each Connector element then edit or add the "address=" field for each connector and specify the appropriate network IP address. The following is an example using a random IP address:

EXAMPLE:
<Connector
port="8443"
address="192.168.0.145"
...
/>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24681r426471_chk'
  tag severity: 'low'
  tag gid: 'V-223009'
  tag rid: 'SV-223009r615938_rule'
  tag stig_id: 'TCAT-AS-001730'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-24670r426472_fix'
  tag 'documentable'
  tag legacy: ['SV-111541', 'V-102601']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
