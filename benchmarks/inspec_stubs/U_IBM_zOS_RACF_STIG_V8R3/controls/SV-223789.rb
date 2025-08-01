control 'SV-223789' do
  title 'The IBM z/OS systems requiring data-at-rest protection must properly employ IBM DS8880 for full disk encryption.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.'
  desc 'check', "Determine if IBM's DS8880 Disks are in use.

If they are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25462r571982_chk'
  tag severity: 'medium'
  tag gid: 'V-223789'
  tag rid: 'SV-223789r604139_rule'
  tag stig_id: 'RACF-OS-000330'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-25450r515056_fix'
  tag 'documentable'
  tag legacy: ['SV-107389', 'V-98285']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
