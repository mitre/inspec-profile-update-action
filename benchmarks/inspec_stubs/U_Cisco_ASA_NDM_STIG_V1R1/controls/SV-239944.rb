control 'SV-239944' do
  title 'The Cisco ASA must be running an operating system release that is currently supported by Cisco Systems.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Verify the ASA is in compliance with this requirement by having the ASA administrator enter the following command. 

show version

Verify the release is still supported by Cisco. All releases supported by Cisco can be found at the following URL:

https://www.cisco.com/c/en/us/products/security/asa-firepower-services/eos-eol-notice-listing.html 

If the ASA is not running a supported release, this is a finding.'
  desc 'fix', 'Upgrade the ASA to a supported release.'
  impact 0.7
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43177r666193_chk'
  tag severity: 'high'
  tag gid: 'V-239944'
  tag rid: 'SV-239944r666195_rule'
  tag stig_id: 'CASA-ND-001420'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-43136r666194_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
