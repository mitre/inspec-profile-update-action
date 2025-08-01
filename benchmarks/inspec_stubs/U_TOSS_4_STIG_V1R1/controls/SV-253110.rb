control 'SV-253110' do
  title 'TOSS must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

$ sudo cat /etc/toss-release
toss-release-4.3-3

Current End of support for TOSS 4.3 is 30 April 2022.

Current End of support for TOSS 4.4 is 30 November 2023.

Current End of support for TOSS 4.5 is 30 April 2023.

Current End of support for TOSS 4.6 is 30 November 2023.

Current End of support for TOSS 4.7 is 30 April 2024.

Current End of support for TOSS 4.8 is 31 May 2029.

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of TOSS.'
  impact 0.7
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56563r825000_chk'
  tag severity: 'high'
  tag gid: 'V-253110'
  tag rid: 'SV-253110r825002_rule'
  tag stig_id: 'TOSS-04-040690'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56513r825001_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
