control 'SV-221553' do
  title 'Debugging and trace information used to diagnose OHS must be disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "TraceEnable" directive at the OHS server and virtual host configuration scopes.

3. If the directive not set to "Off", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "TraceEnable" directive at the OHS server and virtual host configuration scopes.

3. Set the "TraceEnable" directive to a value of "Off", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23268r415338_chk'
  tag severity: 'medium'
  tag gid: 'V-221553'
  tag rid: 'SV-221553r879655_rule'
  tag stig_id: 'OH12-1X-000353'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-23257r415339_fix'
  tag 'documentable'
  tag legacy: ['SV-78981', 'V-64491']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
