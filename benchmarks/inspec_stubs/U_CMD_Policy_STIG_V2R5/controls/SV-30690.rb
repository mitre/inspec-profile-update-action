control 'SV-30690' do
  title 'Site physical security policy must include a statement outlining whether CMDs with digital cameras (still and video) are permitted or prohibited on or in this DoD facility.'
  desc 'Mobile devices with cameras are easily used to photograph sensitive information and areas if not addressed. Sites must establish, document, and train on how to mitigate this threat.'
  desc 'check', 'This requirement applies to mobile operating system (OS) CMDs.

Work with traditional reviewer to review site’s physical security policy. Verify the site addresses CMDs with embedded cameras.

If there is no written physical security policy outlining whether CMDs with cameras are permitted or prohibited on or in this DoD facility, this is a finding.'
  desc 'fix', 'Update the security documentation to include a statement outlining whether CMDs with digital cameras (still and video) are allowed in the facility.'
  impact 0.3
  ref 'DPMS Target Smartphone Handheld Policy'
  tag check_id: 'C-31111r4_chk'
  tag severity: 'low'
  tag gid: 'V-24953'
  tag rid: 'SV-30690r4_rule'
  tag stig_id: 'WIR-SPP-001'
  tag gtitle: 'Site CMD camera policy'
  tag fix_id: 'F-27579r3_fix'
  tag 'documentable'
  tag responsibility: ['Security Manager', 'System Administrator']
  tag ia_controls: 'ECWN-1'
end
