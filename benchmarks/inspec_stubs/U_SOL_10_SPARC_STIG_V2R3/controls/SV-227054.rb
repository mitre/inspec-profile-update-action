control 'SV-227054' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'check', 'Verify no interface is configured to use DHCP.
# ls /etc/dhcp.*
If any file is found, this is a finding.'
  desc 'fix', 'Delete the DHCP client configuration.
# rm /etc/dhcp.*'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29216r485531_chk'
  tag severity: 'medium'
  tag gid: 'V-227054'
  tag rid: 'SV-227054r603265_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29204r485532_fix'
  tag 'documentable'
  tag legacy: ['V-22548', 'SV-26931']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
