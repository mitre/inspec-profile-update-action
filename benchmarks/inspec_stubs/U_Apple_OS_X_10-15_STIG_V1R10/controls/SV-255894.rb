control 'SV-255894' do
  title 'The macOS system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'As of November 2022, Apple is no longer releasing security updates for macOS 10.15 (Catalina).

Verify the operating system version. Click the Apple icon on the menu at the top left corner of the screen, and select the “About This Mac” option. The name of the macOS release installed appears on the Overview tab in the resulting window. The precise version number installed is displayed below.

If the version is 10.15 or older, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-59568r877374_chk'
  tag severity: 'high'
  tag gid: 'V-255894'
  tag rid: 'SV-255894r877376_rule'
  tag stig_id: 'AOSX-15-100001'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-59511r877375_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
