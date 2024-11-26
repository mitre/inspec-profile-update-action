control 'SV-222957' do
  title 'xpoweredBy attribute must be disabled.'
  desc 'Individual connectors can be configured to display the Tomcat server info to clients. This information can be used to identify Tomcat versions which can be useful to attackers for identifying vulnerable versions of Tomcat. Individual connectors must be checked for the xpoweredBy attribute to ensure they do not pass Tomcat server info to clients.'
  desc 'check', 'From the Tomcat server run the following OS command:

sudo cat $CATALINA_BASE/conf/server.xml |grep -i -C4 xpoweredby.

If any connector elements contain xpoweredBy="true", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, edit the $CATALINA_BASE/conf/server.xml file.

Examine each <Connector> </Connector> element, if the element contains xpoweredBy="true", modify the statement to read ", xpoweredBy="false".

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24629r426315_chk'
  tag severity: 'low'
  tag gid: 'V-222957'
  tag rid: 'SV-222957r879587_rule'
  tag stig_id: 'TCAT-AS-000550'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24618r426316_fix'
  tag 'documentable'
  tag legacy: ['SV-111439', 'V-102497']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
