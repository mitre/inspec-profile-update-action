control 'SV-252707' do
  title 'The macOS system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'As of November 2021, Apple is no longer releasing security updates for macOS 10.14 (Mojave).

Verify the operating system version.  Click the Apple icon on the menu at the top left corner of the screen, and select the “About This Mac” option.  The name of the macOS release installed appears on the Overview tab in the resulting window. The precise version number installed is displayed below.

If the version is 10.14 or older, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-56163r819153_chk'
  tag severity: 'high'
  tag gid: 'V-252707'
  tag rid: 'SV-252707r819155_rule'
  tag stig_id: 'AOSX-14-100001'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56113r819154_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
