control 'SV-243447' do
  title 'The Windows PAW must be configured with a vendor-supported version of Windows 11 and applicable security patches that are DOD approved.'
  desc 'Older versions of operating systems usually contain vulnerabilities that have been fixed in later released versions. In addition, most operating system patches contain fixes for recently discovered security vulnerabilities. Due to the highly privileged activities of a PAW, it must be maintained at the highest security posture possible and therefore must have one of the current vendor-supported operating system versions installed.'
  desc 'check', 'Determine the current approved versions of Windows 11.

Talk to the authorizing official (AO) staff, information system security manager (ISSM), or PAW system administrator to determine the approved versions of Windows 11.

Review the configuration of the PAW and determine which version of Windows is installed on the PAW.

Verify the installed Windows 11 version is an approved version.

If the installed Windows 11 version on the PAW is not the same as an approved version, this is a finding.'
  desc 'fix', %q(Install one of the current vendor-supported versions of Windows 11 on site PAWs, including the most recently released patches.

Note: There is no central list in the DOD of "approved" operating system versions. The Microsoft website will list supported versions of Windows 11 and patches. If a STIG is available for one or more of the vendor-supported versions of Windows 11, the version can be considered to be DOD approved. Local AOs usually have implemented a procedure for testing Windows updates before they are deployed. Check with the local AO's staff to determine the latest approved version of Windows 11.)
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46722r921971_chk'
  tag severity: 'medium'
  tag gid: 'V-243447'
  tag rid: 'SV-243447r921973_rule'
  tag stig_id: 'WPAW-00-000700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46679r921972_fix'
  tag 'documentable'
  tag legacy: ['V-78151', 'SV-92857']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
