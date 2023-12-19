control 'SV-30690' do
  title 'Site physical security policy must include a statement outlining whether mobile devices with digital cameras (still and video) are permitted or prohibited on or in this DoD facility.'
  desc 'Mobile devices with cameras are easily used to photograph sensitive information and areas if not addressed. Sites must establish, document, and train on how to mitigate this threat.'
  desc 'check', 'This requirement applies to mobile operating system (OS) mobile devices.

Work with traditional reviewer to review site’s physical security policy. Verify the policy addresses mobile devices CMDs with embedded cameras.

If there is no written physical security policy outlining whether mobile devices with cameras are permitted or prohibited on or in this DoD facility, this is a finding.'
  desc 'fix', 'Update the security documentation to include a statement outlining whether mobile devices with digital cameras (still and video) are allowed in the facility.'
  impact 0.3
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-31111r5_chk'
  tag severity: 'low'
  tag gid: 'V-24953'
  tag rid: 'SV-30690r5_rule'
  tag stig_id: 'WIR-SPP-001'
  tag gtitle: 'Site mobile device camera policy'
  tag fix_id: 'F-27579r4_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Security Manager']
end
