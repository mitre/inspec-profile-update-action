control 'SV-213522' do
  title 'Remote access to JMX subsystem must be disabled.'
  desc 'The JMX subsystem allows you to trigger JDK and application management operations remotely.  In a managed domain configuration, the JMX subsystem is removed by default. For a standalone configuration, it is enabled by default and must be removed.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script to start the Command Line Interface (CLI).
Connect to the server and authenticate.

For a Managed Domain configuration, you must check each profile name:

For each PROFILE NAME, run the command:
"ls /profile=<PROFILE NAME>/subsystem=jmx/remoting-connector"

For a Standalone configuration:
"ls /subsystem=jmx/remoting-connector"

If "jmx" is returned, this is a finding.'
  desc 'fix', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script to start the Command Line Interface (CLI).
Connect to the server and authenticate.

For a Managed Domain configuration you must check each profile name:

For each PROFILE NAME, run the command:
"/profile=<PROFILE NAME>/subsystem=jmx/remoting-connector=jmx:remove"

For a Standalone configuration:
"/subsystem=jmx/remoting-connector=jmx:remove"'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14745r296232_chk'
  tag severity: 'medium'
  tag gid: 'V-213522'
  tag rid: 'SV-213522r615939_rule'
  tag stig_id: 'JBOS-AS-000240'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-14743r296233_fix'
  tag 'documentable'
  tag legacy: ['SV-76759', 'V-62269']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
