control 'SV-239738' do
  title 'VAMI must have debug logging disabled.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage, may be displayed. 

Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc 'check', 'At the command prompt, execute the following command: 

# /opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf|grep "debug.log-request-handling"

Expected result:

    debug.log-request-handling        = "disable"

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Add or reconfigure the following value:

debug.log-request-handling = "disable"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 VAMI-lighttpd'
  tag check_id: 'C-42971r679322_chk'
  tag severity: 'medium'
  tag gid: 'V-239738'
  tag rid: 'SV-239738r679324_rule'
  tag stig_id: 'VCLD-67-000031'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-42930r679323_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
