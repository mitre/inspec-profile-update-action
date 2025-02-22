control 'SV-258990' do
  title 'The vCenter STS service shutdown port must be disabled.'
  desc 'Tomcat by default listens on TCP port 8005 to accept shutdown requests. By connecting to this port and sending the SHUTDOWN command, all applications within Tomcat are halted. The shutdown port is not exposed to the network as it is bound to the loopback interface. Setting the port to "-1" in $CATALINA_BASE/conf/server.xml instructs Tomcat to not listen for the shutdown command.'
  desc 'check', %q(At the command prompt, run the following commands:

# xmllint --xpath "//Server/@port" /usr/lib/vmware-sso/vmware-sts/conf/server.xml
# grep 'base.shutdown.port' /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Example results:

port="${base.shutdown.port}"
base.shutdown.port=-1

If "port" does not equal "${base.shutdown.port}", this is a finding.

If "base.shutdown.port" does not equal "-1", this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Add or modify the setting "base.shutdown.port=-1" in the "catalina.properties" file.

Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Configure the <Server> node with the value:

port="${base.shutdown.port}"

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Secure Token Service (STS)'
  tag check_id: 'C-62730r934626_chk'
  tag severity: 'medium'
  tag gid: 'V-258990'
  tag rid: 'SV-258990r934628_rule'
  tag stig_id: 'VCST-80-000134'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62639r934627_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
