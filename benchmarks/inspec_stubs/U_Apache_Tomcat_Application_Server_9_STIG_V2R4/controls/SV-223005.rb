control 'SV-223005' do
  title 'ENFORCE_ENCODING_IN_GET_WRITER must be set to true.'
  desc 'Some clients try to guess the character encoding of text media when the mandated default of ISO-8859-1 should be used. Some browsers will interpret as UTF-7 when the characters are safe for ISO-8859-1. This can create the potential for a XSS attack. To defend against this, enforce_encoding_in_get_writer must be set to true.'
  desc 'check', 'From the Tomcat server as a privileged user, run the following command:

sudo grep -i  enforce_encoding /etc/systemd/system/tomcat.service 

If there are no results, or if the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER is not ="true", this is a finding.'
  desc 'fix', "From the Tomcat server as a privileged user: 

Edit the /etc/systemd/system/tomcat.service file, and either add or edit the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER setting.

Set the org.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true 

EXAMPLE:
Environment='CATALINA_OPTS -Dorg.apache.catalina.connector.response.ENFORCE_ENCODING_IN_GET_WRITER=true'

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload"
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24677r426459_chk'
  tag severity: 'medium'
  tag gid: 'V-223005'
  tag rid: 'SV-223005r615938_rule'
  tag stig_id: 'TCAT-AS-001690'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-24666r426460_fix'
  tag 'documentable'
  tag legacy: ['SV-111533', 'V-102593']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
