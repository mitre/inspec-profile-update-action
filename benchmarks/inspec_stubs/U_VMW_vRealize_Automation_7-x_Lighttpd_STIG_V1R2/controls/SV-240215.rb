control 'SV-240215' do
  title 'Lighttpd must limit the number of simultaneous requests.'
  desc '<0> [object Object]'
  desc 'check', %q(At the command prompt, execute the following command:

grep 'server.max-connections = 1024' /opt/vmware/etc/lighttpd/lighttpd.conf

If the "server.max-connections" is not set to "1024", commented out, or does not exist, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf   

Configure the "lighttpd.conf" file with the following value:

server.max-connections = 1024'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43448r667820_chk'
  tag severity: 'medium'
  tag gid: 'V-240215'
  tag rid: 'SV-240215r879511_rule'
  tag stig_id: 'VRAU-LI-000005'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-43407r667821_fix'
  tag legacy: ['SV-99869', 'V-89219']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
