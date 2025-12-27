control 'SV-203661' do
  title 'The operating system must protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'Verify the operating system protects the confidentiality and integrity of all information at rest. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect the confidentiality and integrity of all information at rest.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3786r557228_chk'
  tag severity: 'medium'
  tag gid: 'V-203661'
  tag rid: 'SV-203661r557230_rule'
  tag stig_id: 'SRG-OS-000185-GPOS-00079'
  tag gtitle: 'SRG-OS-000185'
  tag fix_id: 'F-3786r557229_fix'
  tag 'documentable'
  tag legacy: ['SV-71137', 'V-56877']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
