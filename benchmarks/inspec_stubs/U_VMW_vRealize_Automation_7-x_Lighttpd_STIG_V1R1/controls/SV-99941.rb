control 'SV-99941' do
  title 'Lighttpd must disable directory browsing.'
  desc 'If not disabled, the directory listing feature can be used to facilitate a directory traversal exploit. Directory listing must be disabled.

Lighttpd provides a configuration setting, dir-listing.activate, that must be set properly in order to globally disable directory listing.'
  desc 'check', %q(At the command prompt, execute the following command:

grep '^dir-listing.activate' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value for "dir-listing.activate" is not set to "disable", this is a finding.)
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

 dir-listing.activate  = "disable"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89291'
  tag rid: 'SV-99941r1_rule'
  tag stig_id: 'VRAU-LI-000345'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-96033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
