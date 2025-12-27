control 'SV-108147' do
  title 'The operating system must be a supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.'
  desc 'check', 'As of September 2019, Apple is no longer releasing security updates for macOS 10.12 (Sierra).

Verify the operating system version.  Click the Apple icon on the menu at the top left corner of the screen, and select the “About This Mac” option.  The name of the macOS release installed appears on the Overview tab in the resulting window. The precise version number installed is displayed below.

If the version is 10.12 or older, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of the operating system.'
  impact 0.7
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-97887r1_chk'
  tag severity: 'high'
  tag gid: 'V-99043'
  tag rid: 'SV-108147r1_rule'
  tag stig_id: 'AOSX-12-000001'
  tag gtitle: 'AOSX-12-000001'
  tag fix_id: 'F-104723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
