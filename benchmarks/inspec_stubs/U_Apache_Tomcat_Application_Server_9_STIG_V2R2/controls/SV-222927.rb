control 'SV-222927' do
  title 'Secured connectors must be configured to use strong encryption ciphers.'
  desc '<0> [object Object]'
  desc 'check', 'From the Tomcat server console, run the following command:

sudo grep -i ciphers $CATALINA_BASE/conf/server.xml.

Examine each <Connector/> element that is not a redirect to a secure port. Identify the ciphers that are configured on each connector and determine if any of the ciphers are not secure.

For a list of approved ciphers, refer to NIST SP 800-52 section 3.3.1.1.

If insecure ciphers are configured for use, this is a finding.'
  desc 'fix', 'As a privileged user on the Tomcat server, edit the $CATALINA_BASE/conf/server.xml and modify the <Connector/> element.

Add the SSLEnabledProtocols="TLSv1.2" setting to the connector or modify the existing setting.

Set SSLEnabledProtocols="TLSv1.2". Save the server.xml file and restart Tomcat:
sudo systemctl restart tomcat
sudo systemctl reload-daemon'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24599r426225_chk'
  tag severity: 'medium'
  tag gid: 'V-222927'
  tag rid: 'SV-222927r615938_rule'
  tag stig_id: 'TCAT-AS-000020'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-24588r426226_fix'
  tag legacy: ['SV-111373', 'V-102429']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
