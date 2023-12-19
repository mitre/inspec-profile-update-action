control 'SV-99829' do
  title 'HAProxy must not be started with the debug switch.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc 'check', "At the command prompt, execute the following command:

ps aux | grep '[h]aproxy' | grep '\\s\\-d\\s'

If the command returns any value, this is a finding."
  desc 'fix', 'Restart the HAProxy without the debug command line argument, which is "-d".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88871r2_chk'
  tag severity: 'medium'
  tag gid: 'V-89179'
  tag rid: 'SV-99829r1_rule'
  tag stig_id: 'VRAU-HA-000320'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-95921r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
