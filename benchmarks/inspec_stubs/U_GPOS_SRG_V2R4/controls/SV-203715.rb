control 'SV-203715' do
  title 'The operating system must enforce dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.'
  desc 'An authorized user may intentionally or accidentally move or delete audit records without those specific actions being authorized.

All bulk manipulation of audit information must be authorized via automatic processes. Any manual manipulation of audit information must require dual authorization. Dual authorization mechanisms require the approval of two authorized individuals to execute.'
  desc 'check', 'Verify the operating system enforces dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3840r375152_chk'
  tag severity: 'medium'
  tag gid: 'V-203715'
  tag rid: 'SV-203715r793165_rule'
  tag stig_id: 'SRG-OS-000360-GPOS-00147'
  tag gtitle: 'SRG-OS-000360'
  tag fix_id: 'F-3840r375153_fix'
  tag 'documentable'
  tag legacy: ['V-57185', 'SV-71445']
  tag cci: ['CCI-000366', 'CCI-001896']
  tag nist: ['CM-6 b', 'AU-9 (5)']
end
