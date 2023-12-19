control 'SV-221447' do
  title 'A public OHS installation, if hosted on the NIPRNet, must be isolated in an accredited DoD DMZ Extension.'
  desc 'To minimize exposure of private assets to unnecessary risk by attackers, public web servers must be isolated from internal systems.  Public web servers are by nature more vulnerable to attack from publically based sources, such as the public Internet. Once compromised, a public web server might be used as a base for further attack on private resources, unless additional layers of protection are implemented. Public web servers must be located in a DoD DMZ Extension, if hosted on the NIPRNet, with carefully controlled access. Failure to isolate resources in this way increase risk that private assets are exposed to attacks from public sources.'
  desc 'check', '1. As required, confirm with the OHS Administrator that OHS is installed in a DMZ and isolated from internal systems.

2. If not, this is a finding.'
  desc 'fix', '1. Relocate the OHS server to be in a DMZ, isolated from internal systems.

2. Confirm that the OHS server only has connections to supporting Application and Database Servers.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23162r415024_chk'
  tag severity: 'medium'
  tag gid: 'V-221447'
  tag rid: 'SV-221447r415026_rule'
  tag stig_id: 'OH12-1X-000209'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23151r415025_fix'
  tag 'documentable'
  tag legacy: ['SV-79147', 'V-64657']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
