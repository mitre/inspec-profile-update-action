control 'SV-99943' do
  title 'Lighttpd must not be configured to use mod_status.'
  desc 'Any application providing too much information in error logs and in administrative messages to the screen risks compromising the data and security of the application and system. The structure and content of error messages needs to be carefully considered by the organization and development team. 

Lighttpd must only generate error messages that provide information necessary for corrective actions without revealing sensitive or potentially harmful information in error logs and administrative messages. The mod_status module generates the status overview of the webserver. The information covers:

uptime
average throughput
current throughput
active connections and their state

While this information is useful on a development system, production systems must not have mod_status enabled.'
  desc 'check', %q(At the command prompt, execute the following command:    

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\.modules/,/\\)/'

If the "mod_status" module is listed, this is a finding.)
  desc 'fix', 'Navigate to and open the /opt/vmware/etc/lighttpd/lighttpd.conf file

Navigate to the "server.modules" section.

In the "server.modules" section, delete the "mod_status" entry.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89293'
  tag rid: 'SV-99943r1_rule'
  tag stig_id: 'VRAU-LI-000350'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-96035r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
