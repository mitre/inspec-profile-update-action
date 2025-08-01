control 'SV-240218' do
  title 'Lighttpd must be configured to use mod_accesslog.'
  desc 'Lighttpd is the administration panel for vRealize Automation. Because it is intended to provide remote access to the appliance, vRA must provide remote access information to external monitoring systems.

mod_accesslog is the module in Lighttpd that configures Lighttpd to share information with external monitoring systems.'
  desc 'check', %q(At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\.modules/,/\\)/'

If the value "mod_accesslog" is not listed, this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to and configure the "server.modules" section with the following value:

mod_accesslog'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43451r667829_chk'
  tag severity: 'medium'
  tag gid: 'V-240218'
  tag rid: 'SV-240218r879521_rule'
  tag stig_id: 'VRAU-LI-000025'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-43410r667830_fix'
  tag 'documentable'
  tag legacy: ['SV-99875', 'V-89225']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
