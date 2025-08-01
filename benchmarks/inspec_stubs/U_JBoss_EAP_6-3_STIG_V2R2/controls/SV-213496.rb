control 'SV-213496' do
  title 'Java permissions must be set for hosted applications.'
  desc 'The Java Security Manager is a java class that manages the external boundary of the Java Virtual Machine (JVM) sandbox, controlling how code executing within the JVM can interact with resources outside the JVM.

The JVM requires a security policy in order to restrict application access.  A properly configured security policy will define what rights the application has to the underlying system.  For example, rights to make changes to files on the host system or to initiate network sockets in order to connect to another system.'
  desc 'check', 'Obtain documentation from the admin that identifies the applications hosted on the JBoss server as well as the corresponding rights the application requires.  For example, if the application requires network socket permissions and file write permissions, those requirements should be documented.

1. Identify the JBoss installation as either domain or standalone and review the relevant configuration file.
For domain installs: JBOSS_HOME/bin/domain.conf
For standalone installs: JBOSS_HOME/bin/standalone.conf

2. Identify the location and name of the security policy by reading the JAVA_OPTS flag -Djava.security.policy=<file name> where <file name> will indicate name and location of security policy.  If the application uses a policy URL, obtain URL and policy file from system admin.

3. Review security policy and ensure hosted applications have the appropriate restrictions placed on them as per documented application functionality requirements.

If the security policy does not restrict application access to host resources as per documented requirements, this is a finding.'
  desc 'fix', 'Configure the Java security manager to enforce access restrictions to the host system resources in accordance with application design and resource requirements.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14719r296154_chk'
  tag severity: 'high'
  tag gid: 'V-213496'
  tag rid: 'SV-213496r615939_rule'
  tag stig_id: 'JBOS-AS-000025'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-14717r296155_fix'
  tag 'documentable'
  tag legacy: ['SV-76707', 'V-62217']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
