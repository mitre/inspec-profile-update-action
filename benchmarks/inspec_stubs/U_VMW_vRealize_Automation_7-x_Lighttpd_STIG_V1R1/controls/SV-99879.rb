control 'SV-99879' do
  title 'Lighttpd must capture, record, and log the IP address associated with a user session.'
  desc 'A user session to a web server is in the context of a user accessing a hosted application that extends to any plug-ins/modules and services that may execute on behalf of the user.

Lighttpd logs user activity in the access.log file using the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures logs all user session information related to the hosted application session. This will enable forensic analysis of server events in case of malicious event.

Lighttpd logs IPv4 addresses as "IPv4-mapped IPv6 addresses". As a result, in the Lighttpd log, client IP addresses will begin with "::ffff:". For example, if the client address was 255.255.255.255, the Lighttpd log will record the address as ::ffff:255.255.255.255.'
  desc 'check', 'At the command prompt, execute the following command:

tail -n 1 /opt/vmware/var/log/lighttpd/access.log

If client IP addresses are not being logged, this is a finding.

Note:  Lighttpd will prepend IPv4 addresses with ::ffff: This is called "IPv4-mapped IPv6 addresses".'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

$HTTP["url"] !~ "(.css|.jpg|.gif|.png|.ico)$" {
  accesslog.filename = log_root + "/access.log"
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89229'
  tag rid: 'SV-99879r1_rule'
  tag stig_id: 'VRAU-LI-000045'
  tag gtitle: 'SRG-APP-000093-WSR-000053'
  tag fix_id: 'F-95971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
