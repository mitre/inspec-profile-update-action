control 'SV-240266' do
  title 'Lighttpd must not be configured to listen to unnecessary ports.'
  desc 'Web servers must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability assessments.

Lighttpd will listen on ports that are specified with the server.port configuration parameter. Lighttpd listens to port 5480 to provide remote access to the Virtual Appliance Management Interface (vAMI). Lighttpd must not be configured to listen to any other port.'
  desc 'check', %q(At the command prompt, execute the following command: 

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '$0 ~ /server\.port/ { print }'  

If any value returned other than "server.port=5480", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Note: Do not delete the entry for "server.port=5480"

Delete all other server.port entries.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43499r667973_chk'
  tag severity: 'medium'
  tag gid: 'V-240266'
  tag rid: 'SV-240266r879756_rule'
  tag stig_id: 'VRAU-LI-000430'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-43458r667974_fix'
  tag 'documentable'
  tag legacy: ['SV-99957', 'V-89307']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
