control 'SV-99877' do
  title 'Lighttpd must generate log records for system startup and shutdown.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. 

Lighttpd records system event information in the error.log file. Included in the file is system start and stop events.'
  desc 'check', "At the command prompt, execute the following command:

egrep 'server\\sstarted|server\\sstopped' /opt/vmware/var/log/lighttpd/error.log

If server stopped and server started times are not listed, this is a finding."
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

server.errorlog = log_root + "/error.log"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89227'
  tag rid: 'SV-99877r1_rule'
  tag stig_id: 'VRAU-LI-000035'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-95969r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
