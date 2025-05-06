control 'SV-240275' do
  title 'Lighttpd must disable IP forwarding.'
  desc 'IP forwarding permits Lighttpd to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers. Lighttpd is not implemented as a router.

With the url.redirect configuration parameter, Lighttpd can be configured to forward IPv4 packets. This configuration parameter is prohibited, unless Lighttpd is redirecting packets to localhost, 127.0.0.1.'
  desc 'check', "At the command prompt, execute the following command: 

grep -E 'url\\.redirect' /opt/vmware/etc/lighttpd/lighttpd.conf | grep -v '^#'

If any values are returned, this is a finding."
  desc 'fix', 'Navigate to /opt/vmware/etc/lighttpd/lighttpd.conf

In the "lighttpd.conf" file, delete all lines that are returned containing url.redirect returned.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43508r668000_chk'
  tag severity: 'medium'
  tag gid: 'V-240275'
  tag rid: 'SV-240275r879887_rule'
  tag stig_id: 'VRAU-LI-000515'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-43467r668001_fix'
  tag 'documentable'
  tag legacy: ['SV-99975', 'V-89325']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
