control 'SV-213497' do
  title 'The Java Security Manager must be enabled for the JBoss application server.'
  desc 'The Java Security Manager is a java class that manages the external boundary of the Java Virtual Machine (JVM) sandbox, controlling how code executing within the JVM can interact with resources outside the JVM.

The Java Security Manager uses a security policy to determine whether a given action will be
permitted or denied.

To protect the host system, the JBoss application server must be run within the Java Security Manager.'
  desc 'check', 'To determine if the Java Security Manager is enabled for JBoss, you must examine the startup commands.  JBoss can be configured to run in either "domain" or a "standalone" mode.  JBOSS_HOME is the variable home directory for the JBoss installation.  Use relevant OS commands to navigate the file system.

A. For a managed domain installation, review the domain.conf and domain.conf.bat files:

JBOSS_HOME/bin/domain.conf
JBOSS_HOME/bin/domain.conf.bat

In domain.conf file, ensure there is a JAVA_OPTS flag that loads the Java Security Manager as well as a relevant Java Security policy.   The following is an example:

JAVA_OPTS="$JAVA_OPTS -Djava.security.manager -Djava.security.policy==$PWD/server.policy -Djboss.home.dir=/path/to/JBOSS_HOME -Djboss.modules.policy-permissions=true"

In domain.conf.bat file, ensure JAVA_OPTS flag is set.  The following is an example:

set "JAVA_OPTS=%JAVA_OPTS% -Djava.security.manager -Djava.security.policy==/path/to/server.policy -Djboss.home.dir=/path/to/JBOSS_HOME -Djboss.modules.policy-permissions=true"

B. For a standalone installation, review the standalone.conf and standalone.conf.bat files:

JBOSS_HOME/bin/standalone.conf
JBOSS_HOME/bin/standalone.conf.bat

In the standalone.conf file, ensure the JAVA_OPTS flag is set.  The following is an example:

JAVA_OPTS="$JAVA_OPTS -Djava.security.manager -Djava.security.policy==$PWD/server.policy -Djboss.home.dir=$JBOSS_HOME -Djboss.modules.policy-permissions=true"

In the standalone.conf.bat file, ensure the JAVA_OPTS flag is set.  The following is an example:

set "JAVA_OPTS=%JAVA_OPTS% -Djava.security.manager -Djava.security.policy==/path/to/server.policy -Djboss.home.dir=%JBOSS_HOME% -Djboss.modules.policy-permissions=true"  

If the security manager is not enabled and a security policy not defined, this is a finding.'
  desc 'fix', 'For a domain installation:
Enable the respective JAVA_OPTS flag in both the domain.conf and the domain.conf.bat files.

For a standalone installation:
Enable the respective JAVA_OPTS flag in both the standalone.conf and the standalone.conf.bat files.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14720r296157_chk'
  tag severity: 'high'
  tag gid: 'V-213497'
  tag rid: 'SV-213497r615939_rule'
  tag stig_id: 'JBOS-AS-000030'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-14718r296158_fix'
  tag 'documentable'
  tag legacy: ['SV-76715', 'V-62225']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
