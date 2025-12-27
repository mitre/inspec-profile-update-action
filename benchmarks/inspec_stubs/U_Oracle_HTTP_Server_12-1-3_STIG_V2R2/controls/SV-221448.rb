control 'SV-221448' do
  title 'A private OHS installation must be located on a separate controlled access subnet.'
  desc 'Private web servers, which host sites that serve controlled access data, must be protected from outside threats in addition to insider threats. Insider threat may be accidental or intentional but, in either case, can cause a disruption in service of the web server. To protect the private web server from these threats, it must be located on a separate controlled access subnet and must not be a part of the public DMZ that houses the public web servers. It also cannot be located inside the enclave as part of the local general population LAN.'
  desc 'check', "1. As required, confirm with the OHS Administrator that OHS is installed on a separately controlled access subnet, not part of any DMZ.

2. Confirm that the OHS server is isolated from access by the LAN's general population.

3. If not, this is a finding."
  desc 'fix', "1. Relocate the OHS server to be on a local subnet, isolated from the DMZ.

2. Remove access to the OHS server from the LAN's general population."
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23163r415027_chk'
  tag severity: 'medium'
  tag gid: 'V-221448'
  tag rid: 'SV-221448r879887_rule'
  tag stig_id: 'OH12-1X-000210'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23152r415028_fix'
  tag 'documentable'
  tag legacy: ['SV-79149', 'V-64659']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
