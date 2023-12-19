control 'SV-206413' do
  title 'Debugging and trace information used to diagnose the web server must be disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if debugging and trace information are enabled.

If the web server is configured with debugging and trace information enabled, this is a finding.'
  desc 'fix', 'Configure the web server to minimize the information given to clients on error conditions by disabling debugging and trace information.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6674r377831_chk'
  tag severity: 'medium'
  tag gid: 'V-206413'
  tag rid: 'SV-206413r879655_rule'
  tag stig_id: 'SRG-APP-000266-WSR-000160'
  tag gtitle: 'SRG-APP-000266'
  tag fix_id: 'F-6674r377832_fix'
  tag 'documentable'
  tag legacy: ['SV-54432', 'V-41855']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
