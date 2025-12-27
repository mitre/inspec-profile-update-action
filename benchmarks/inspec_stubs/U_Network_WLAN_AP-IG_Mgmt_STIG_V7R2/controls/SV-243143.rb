control 'SV-243143' do
  title 'The network device must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Have the administrator display the operating system version in operation. The operating system must be current, with related IAVMs addressed.

If the device is using an OS that does not meet all IAVMs or is not currently supported by the vendor, this is a finding.'
  desc 'fix', 'Update the operating system to a supported version that addresses all related IAVMs.'
  impact 0.7
  ref 'DPMS Target Network WLAN AP-IG Mgmt'
  tag check_id: 'C-46418r719882_chk'
  tag severity: 'high'
  tag gid: 'V-243143'
  tag rid: 'SV-243143r879887_rule'
  tag stig_id: 'WLAN-ND-001000'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-46375r719883_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
