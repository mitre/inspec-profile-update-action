control 'SV-213468' do
  title 'The network device  must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify that the network device is in compliance with this requirement. If the network device is not running an operating system release that is currently supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade the network device to an operating system that is supported by the vendor.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-14693r382088_chk'
  tag severity: 'high'
  tag gid: 'V-213468'
  tag rid: 'SV-213468r401224_rule'
  tag stig_id: 'SRG-APP-000516-NDM-000351'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-14691r382089_fix'
  tag 'documentable'
  tag legacy: ['SV-108123', 'V-99019']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
