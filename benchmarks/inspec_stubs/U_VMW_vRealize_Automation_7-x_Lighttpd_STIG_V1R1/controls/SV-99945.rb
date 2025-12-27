control 'SV-99945' do
  title 'Lighttpd must have debug logging disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.

While this information is useful on a development system, production systems must not have debug logging enabled.'
  desc 'check', %q(At the command prompt, execute the following command:    

grep '^debug.log-request-handling' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value for "debug.log-request-handling" is not set to "disable", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following: 

debug.log-request-handling = "disable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88987r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89295'
  tag rid: 'SV-99945r1_rule'
  tag stig_id: 'VRAU-LI-000355'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-96037r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
