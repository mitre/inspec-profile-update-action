control 'SV-241594' do
  title 'tc Server ALL must generate log records for system startup and shutdown.'
  desc 'Logging must be started as soon as possible when a service starts and when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go un-logged.

During start, tc Server reports system messages onto STDOUT and STDERR. These messages will be logged if the initialization script is configured correctly. For historical reasons, the standard log file for this is called “catalina.out”.'
  desc 'check', 'At the command prompt, execute the following command:

more  /storage/log/vcops/log/product-ui/catalina.out

Verify that tc Server start and stop events are being logged. 

If the tc Server start and stop events are not being recorded, this is a finding.

Note: The tc Server service is referred to as Catalina in the log.'
  desc 'fix', %q(Navigate to and open /opt/pivotal/pivotal-tc-server-standard/tomcat-7.0.57.B.RELEASE/bin/catalina.sh.

Navigate to and locate the start block : "elif [ "$1" = "start" ] ; then".

Navigate to and locate both “eval” statements: 

"org.apache.catalina.startup.Bootstrap "$@" start \" 

Add this statement immediately below both of the “eval” statements: 

'>> "$CATALINA_OUT" 2>&1 "&"')
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44870r684107_chk'
  tag severity: 'medium'
  tag gid: 'V-241594'
  tag rid: 'SV-241594r879559_rule'
  tag stig_id: 'VROM-TC-000115'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-44829r683643_fix'
  tag 'documentable'
  tag legacy: ['SV-99467', 'V-88817']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
