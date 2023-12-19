control 'SV-207219' do
  title 'The VPN Gateway must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication and identification enables non-organizational users to gain access to the network or possibly a VPN gateway that provides opportunity for intruders to compromise resources within the network infrastructure.

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user.'
  desc 'check', 'Configure the VPN Gateway to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

If the VPN Gateway does not uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users), this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7479r378278_chk'
  tag severity: 'medium'
  tag gid: 'V-207219'
  tag rid: 'SV-207219r608988_rule'
  tag stig_id: 'SRG-NET-000169-VPN-000610'
  tag gtitle: 'SRG-NET-000169'
  tag fix_id: 'F-7479r378279_fix'
  tag 'documentable'
  tag legacy: ['SV-106255', 'V-97117']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
