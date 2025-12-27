control 'SV-224012' do
  title 'The IBM z/OS systems requiring data at rest protection must properly employ IBM DS8880 for full disk encryption.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.'
  desc 'check', "Determine if IBM's DS880 disks are in use.

If they are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25685r516435_chk'
  tag severity: 'medium'
  tag gid: 'V-224012'
  tag rid: 'SV-224012r561402_rule'
  tag stig_id: 'TSS0-OS-000160'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-25673r516436_fix'
  tag 'documentable'
  tag legacy: ['SV-107837', 'V-98733']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
