control 'SV-222963' do
  title 'JMX authentication must be secured.'
  desc 'Java Management Extensions (JMX) provides the means to remotely manage the Java VM. When enabling the JMX agent for remote monitoring, the user must enable authentication.'
  desc 'check', 'From the Tomcat server run the following command:

sudo grep -I jmxremote.authenticate /etc/systemd/system/tomcat.service
sudo ps -ef |grep -i jmxremote

If the results are blank, this is not a finding.

If the results include:

-Dcom.sun.management.jmxremote.authenticate=false, this is a finding.'
  desc 'fix', "If using JMX for management of the Tomcat server, start the Tomcat server by adding the following command line flags to the systemd startup scripts in /etc/systemd/system/tomcat.service.

Environment='CATALINA_OPTS -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.authenticate=true -Dcom.sun.management.jmxremote.ssl=true'

sudo systemctl start tomcat
sudo systemctl daemon-reload"
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24635r426333_chk'
  tag severity: 'medium'
  tag gid: 'V-222963'
  tag rid: 'SV-222963r615938_rule'
  tag stig_id: 'TCAT-AS-000610'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag fix_id: 'F-24624r426334_fix'
  tag 'documentable'
  tag legacy: ['SV-111451', 'V-102509']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
