control 'SV-252706' do
  title 'The macOS system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'As of November 2020, Apple is no longer releasing security updates for macOS 10.13 (High Sierra).

Verify the operating system version.  Click the Apple icon on the menu at the top left corner of the screen, and select the “About This Mac” option.  The name of the macOS release installed appears on the Overview tab in the resulting window. The precise version number installed is displayed below.

If the version is 10.13 or older, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-56162r819150_chk'
  tag severity: 'high'
  tag gid: 'V-252706'
  tag rid: 'SV-252706r819152_rule'
  tag stig_id: 'AOSX-13-100001'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56112r819151_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
