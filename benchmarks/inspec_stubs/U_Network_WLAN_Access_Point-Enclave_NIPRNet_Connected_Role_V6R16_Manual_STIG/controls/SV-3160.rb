control 'SV-3160' do
  title 'Network devices must be running a current and supported operating system with all IAVMs addressed.'
  desc 'Network devices not running the latest tested and approved versions of software are vulnerable to network attacks. Running the most current, approved version of system and device software helps the site maintain a stable base of security fixes and patches, as well as enhancements to IP security. Viruses, denial of service attacks, system weaknesses, back doors and other potentially harmful situations could render a system vulnerable, allowing unauthorized access to DoD assets.'
  desc 'check', 'Have the administrator display the OS version in operation. The OS must be current with related IAVMs addressed.

If the device is using an OS that does not meet all IAVMs or currently not supported by the vendor, this is a finding.'
  desc 'fix', 'Update operating system to a supported version that addresses all related IAVMs.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3549r4_chk'
  tag severity: 'medium'
  tag gid: 'V-3160'
  tag rid: 'SV-3160r4_rule'
  tag stig_id: 'NET0700'
  tag gtitle: 'Operating system is not at a current release level.'
  tag fix_id: 'F-3185r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
