control 'SV-78529' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product.  With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'As of 31 December 2015, HPUX 11.23 will no longer be supported by the vendor.

Verify the operating system version:
# uname –r

If the output is:
# B.11.23

This is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-64905r1_chk'
  tag severity: 'high'
  tag gid: 'V-64039'
  tag rid: 'SV-78529r1_rule'
  tag stig_id: 'GEN000100'
  tag gtitle: 'GEN000100'
  tag fix_id: 'F-70083r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
