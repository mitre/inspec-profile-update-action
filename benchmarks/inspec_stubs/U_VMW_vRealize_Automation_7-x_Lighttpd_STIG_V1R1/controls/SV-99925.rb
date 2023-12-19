control 'SV-99925' do
  title 'Lighttpd must be configured to use port 5480.'
  desc "Lighttpd is used as the web server for vRealize Automation's Virtual Appliance Management Interface (vAMI). To segregate appliance management from appliance operation, Lighttpd can be configured to listen on a separate port. Port 5488 is the recommended port setting."
  desc 'check', %q(At the command prompt, execute the following command:

grep '^server.port' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value of "server.port" is not "5480", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Configure the lighttpd.conf file with the following:

server.port = 5480'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89275'
  tag rid: 'SV-99925r1_rule'
  tag stig_id: 'VRAU-LI-000220'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-96017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
