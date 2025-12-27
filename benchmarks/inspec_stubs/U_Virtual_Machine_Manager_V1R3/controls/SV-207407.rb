control 'SV-207407' do
  title 'The VMM must protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within a VMM.

This requirement addresses protection of user-generated data, as well as VMM-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'Verify the VMM protects the confidentiality and integrity of all information at rest.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect the confidentiality and integrity of all information at rest.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7664r365631_chk'
  tag severity: 'medium'
  tag gid: 'V-207407'
  tag rid: 'SV-207407r379084_rule'
  tag stig_id: 'SRG-OS-000185-VMM-000720'
  tag gtitle: 'SRG-OS-000185'
  tag fix_id: 'F-7664r365632_fix'
  tag 'documentable'
  tag legacy: ['V-57015', 'SV-71275']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
