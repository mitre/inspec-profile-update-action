control 'SV-213520' do
  title 'JBoss process owner execution permissions must be limited.'
  desc 'JBoss EAP application server can be run as the OS admin, which is not advised.  Running the application server with admin privileges increases the attack surface by granting the application server more rights than it requires in order to operate.  If the server is compromised, the attacker will have the same rights as the application server, which in that case would be admin rights.  The JBoss EAP server must not be run as the admin user.'
  desc 'check', 'The script that is used to start JBoss determines the mode in which JBoss will operate, which will be in either in standalone mode or domain mode.  Both scripts are installed by default in the <JBOSS_HOME>/bin/ folder.

In addition to running the JBoss server as an interactive script launched from the command line, JBoss can also be started as a service.

The scripts used to start JBoss are:
Red Hat: 
standalone.sh
domain.sh

Windows: 
standalone.bat
domain.bat

Use the relevant OS commands to determine JBoss ownership.

When running as a process: 
Red Hat: "ps -ef|grep -i jboss".
Windows: "services.msc".

Search for the JBoss process, which by default is named "JBOSSEAP6". 

If the user account used to launch the JBoss script or start the JBoss process has admin rights on the system, this is a finding.'
  desc 'fix', 'Run the JBoss server with non-admin rights.'
  impact 0.7
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14743r296226_chk'
  tag severity: 'high'
  tag gid: 'V-213520'
  tag rid: 'SV-213520r615939_rule'
  tag stig_id: 'JBOS-AS-000230'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-14741r296227_fix'
  tag 'documentable'
  tag legacy: ['SV-76755', 'V-62265']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
