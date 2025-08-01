control 'SV-221452' do
  title 'All utility programs, not necessary for operations, must be removed or disabled.'
  desc 'Just as running unneeded services and protocols is a danger to the web server at the lower levels of the OSI model, running unneeded utilities and programs is also a danger at the application layer of the OSI model. Office suites, development tools, and graphical editors are examples of such programs that are troublesome. Individual productivity tools have no legitimate place or use on an enterprise, production web server and they are also prone to their own security risks.'
  desc 'check', '1. Check the server for software that is unnecessary for OHS operation.

2. If the software is unnecessary for OHS, other organization requirements, or is not appropriately patched or supported, this is a finding.'
  desc 'fix', 'Remove any software that is unnecessary for OHS operation, other organization requirements, or is not appropriately patched or supported.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23167r415039_chk'
  tag severity: 'low'
  tag gid: 'V-221452'
  tag rid: 'SV-221452r879887_rule'
  tag stig_id: 'OH12-1X-000215'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23156r415040_fix'
  tag 'documentable'
  tag legacy: ['SV-79157', 'V-64667']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
