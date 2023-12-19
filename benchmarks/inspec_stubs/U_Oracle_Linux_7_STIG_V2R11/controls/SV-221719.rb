control 'SV-221719' do
  title 'The Oracle Linux operating system must be a vendor supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'Verify the version of the operating system is vendor supported.

Check the version of the operating system with the following command:

# cat /etc/oracle-release

Oracle Linux Server release 7.6

Current End of Premier Support for Oracle Linux 7 is Jul 2024 while Extended Support might consider extended term.

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23434r419229_chk'
  tag severity: 'high'
  tag gid: 'V-221719'
  tag rid: 'SV-221719r603260_rule'
  tag stig_id: 'OL07-00-020250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23423r419230_fix'
  tag 'documentable'
  tag legacy: ['V-99175', 'SV-108279']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
