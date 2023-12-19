control 'SV-250569' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered supported if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'ESXi v5 is no longer supported by the vendor. If the server is running ESXi v5, this is a finding.'
  desc 'fix', 'Upgrade to a supported version.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54004r802863_chk'
  tag severity: 'high'
  tag gid: 'V-250569'
  tag rid: 'SV-250569r802864_rule'
  tag stig_id: 'GEN000100-ESXI5-000062'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53958r798705_fix'
  tag 'documentable'
  tag legacy: ['SV-51287', 'V-39429']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
