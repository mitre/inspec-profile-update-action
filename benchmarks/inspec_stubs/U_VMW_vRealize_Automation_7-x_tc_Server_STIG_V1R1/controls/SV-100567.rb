control 'SV-100567' do
  title 'tc Server ALL must generate log records for system startup and shutdown.'
  desc 'Logging must be started as soon as possible when a service starts and when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.

During start, tc Server reports system messages onto STDOUT and STDERR. These messages will be logged if the initialization script is configured correctly. For historical reasons, the standard log file for this is called catalina.out.'
  desc 'check', 'At the command prompt, execute the following command:

more /storage/log/vmware/vco/app-server/catalina.out

Verify that tc Server start and stop events are being logged. 

If the tc Server start and stop events are not being recorded, this is a finding.

Note: The tc Server service is referred to as Catalina in the log.'
  desc 'fix', %q(Navigate to and open /usr/share/tomcat/bin/catalina.sh.

Navigate to and locate the start block : "elif [ "$1" = "start" ] ; then"

Navigate to and locate both "eval" statements : "org.apache.catalina.startup.Bootstrap "$@" start \" 

Add this statement immediately below both of the "eval" statements : '>> "$CATALINA_OUT" 2>&1 "&"')
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89609r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89917'
  tag rid: 'SV-100567r1_rule'
  tag stig_id: 'VRAU-TC-000105'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-96659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
