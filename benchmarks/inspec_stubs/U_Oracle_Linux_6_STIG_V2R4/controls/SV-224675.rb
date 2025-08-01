control 'SV-224675' do
  title 'The Oracle Linux operating system must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

# cat /etc/oracle-release

Oracle Linux release 6.10

Current end of Support for Oracle Linux 6 is 31 March 2024.

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-26366r462519_chk'
  tag severity: 'high'
  tag gid: 'V-224675'
  tag rid: 'SV-224675r603263_rule'
  tag stig_id: 'OL6-00-000010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-26354r462520_fix'
  tag 'documentable'
  tag legacy: ['SV-111303', 'V-102347']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
