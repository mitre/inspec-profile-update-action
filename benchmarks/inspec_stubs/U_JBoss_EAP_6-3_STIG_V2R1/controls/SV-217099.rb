control 'SV-217099' do
  title 'The JBoss server must be configured to bind the management interfaces to only management networks.'
  desc 'JBoss provides multiple interfaces for accessing the system.  By default, these are called "public" and "management".  Allowing non-management traffic to access the JBoss management interface increases the chances of a security compromise.  The JBoss server must be configured to bind the management interface to a network that controls access.  This is usually a network that has been designated as a management network and has restricted access.  Similarly, the public interface must be bound to a network that is not on the same segment as the management interface.'
  desc 'check', 'Obtain documentation and network drawings from system admin that shows the network interfaces on the JBoss server and the networks they are configured for.

If a management network is not used, you may substitute localhost/127.0.0.1 for management address.  If localhost/127.0.0.1 is used for management interface, this is not a finding.

From the JBoss server open the web-based admin console by pointing a browser to HTTP://127.0.0.1:9990.
Log on to the management console with admin credentials.
Select "RUNTIME". 
Expand STATUS by clicking on +.
Expand PLATFORM by clicking on +.
In the "Environment" tab, click the > arrow until you see the "jboss.bind.properties" and the "jboss.bind.properties.management" values.

If the jboss.bind.properties and the jboss.bind.properties.management do not have different IP network addresses assigned, this is a finding.

Review the network documentation.  If access to the management IP address is not restricted, this is a finding.'
  desc 'fix', 'Refer to Section 4.9 of the JBoss EAP 6.3 Installation guide for detailed instructions on how to start JBoss as a service.

Use the following command line parameters to assign the management interface to a specific management network.

These command line flags must be added both when starting JBoss as a service and when starting from the command line.

Substitute your actual network address for the 10.x.x.x addresses provided as an example below.

For a standalone configuration:
JBOSS_HOME/bin/standalone.sh -bmanagement=10.2.2.1 -b 10.1.1.1

JBOSS_HOME/bin/domain.sh -bmanagement=10.2.2.1 -b 10.1.1.1

If a management network is not available, you may substitute localhost/127.0.0.1 for management address.  This will force you to manage the JBoss server from the local host.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-18328r296346_chk'
  tag severity: 'medium'
  tag gid: 'V-217099'
  tag rid: 'SV-217099r615939_rule'
  tag stig_id: 'JBOS-AS-000285'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-18326r296347_fix'
  tag 'documentable'
  tag legacy: ['SV-76773', 'V-62283']
  tag cci: ['CCI-000778', 'CCI-000366']
  tag nist: ['IA-3', 'CM-6 b']
end
