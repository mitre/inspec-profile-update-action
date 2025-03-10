control 'SV-259042' do
  title 'The vCenter Lookup service must limit privileges for creating or modifying hosted application shared files.'
  desc 'Application servers have the ability to specify that the hosted applications use shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that nonprivileged users cannot modify any shared library code at all.

Ensuring the Security Lifecycle Listener element is uncommented and sets a minimum Umask value will allow the server to perform a number of security checks when starting and prevent the service from starting if they fail.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Listener[@className="org.apache.catalina.security.SecurityListener"]' /usr/lib/vmware-lookupsvc/conf/server.xml

Example result:

<Listener className="org.apache.catalina.security.SecurityListener"/>

If the "org.apache.catalina.security.SecurityListener" listener is not present, this is a finding.

If the "org.apache.catalina.security.SecurityListener" listener is configured with a "minimumUmask" and is not "0007", this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to the <Server> node and add or update the "org.apache.catalina.security.SecurityListener" as follows:

<Listener className="org.apache.catalina.security.SecurityListener"/>

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Lookup Service'
  tag check_id: 'C-62782r934782_chk'
  tag severity: 'medium'
  tag gid: 'V-259042'
  tag rid: 'SV-259042r934784_rule'
  tag stig_id: 'VCLU-80-000034'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag fix_id: 'F-62691r934783_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
