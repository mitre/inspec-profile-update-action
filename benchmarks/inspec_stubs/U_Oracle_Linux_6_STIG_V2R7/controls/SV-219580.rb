control 'SV-219580' do
  title 'The system must provide VPN connectivity for communications over untrusted networks.'
  desc 'Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.'
  desc 'check', 'If the system does not communicate over untrusted networks, this is not applicable.

Run the following command to determine if the "libreswan" package is installed: 

# rpm -q libreswan

If the package is not installed, this is a finding.'
  desc 'fix', 'The Libreswan package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks.

The "libreswan" package can be installed with the following command: 

# yum install libreswan'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21305r358280_chk'
  tag severity: 'low'
  tag gid: 'V-219580'
  tag rid: 'SV-219580r793837_rule'
  tag stig_id: 'OL6-00-000321'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21304r358281_fix'
  tag 'documentable'
  tag legacy: ['V-51121', 'SV-65331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
