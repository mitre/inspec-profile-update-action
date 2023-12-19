control 'SV-100575' do
  title 'tc Server ALL must initiate logging during service start-up.'
  desc 'An attacker can compromise a web server during the startup process. If logging is not initiated until all the web server processes are started, key information may be missed and not available during a forensic investigation. To assure all logable events are captured, the web server must begin logging once the first web server process is initiated.

During start, tc Server reports system messages onto STDOUT and STDERR. These messages will be logged if the initialization script is configured correctly. For historical reasons, the standard log file for this is called catalina.out.'
  desc 'check', 'At the command prompt, execute the following command:

more /usr/share/tomcat/bin/catalina.sh

Type /touch "$CATALINA_OUT"

Verify that the start command contains the command ">> "$CATALINA_OUT" 2>&1 "&""

If the command is not correct or is missing, this is a finding.

Note: Use the "Enter" key to scroll down after typing /touch "$CATALINA_OUT"'
  desc 'fix', %q(Navigate to and open Navigate to and open /usr/share/tomcat/bin/catalina.sh.

Navigate to and locate the start block : "elif [ "$1" = "start" ] ; then"

Navigate to and locate both "eval" statements : "org.apache.catalina.startup.Bootstrap "$@" start \" 

Add this statement immediately below both of the "eval" statements : '>> "$CATALINA_OUT" 2>&1 "&"')
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89925'
  tag rid: 'SV-100575r1_rule'
  tag stig_id: 'VRAU-TC-000125'
  tag gtitle: 'SRG-APP-000092-WSR-000055'
  tag fix_id: 'F-96667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
