control 'SV-207467' do
  title 'The VMM must enforce dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.'
  desc 'An authorized user may intentionally or accidentally move or delete audit records without those specific actions being authorized.

All bulk manipulation of audit information must be via authorized automatic processes. Any manual manipulation of audit information must require dual authorization. Dual authorization mechanisms require the approval of two authorized individuals in order to execute.'
  desc 'check', 'Verify the VMM enforces dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce dual authorization for movement and/or deletion of all audit information, when such movement or deletion is not part of an authorized automatic process.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7724r365805_chk'
  tag severity: 'medium'
  tag gid: 'V-207467'
  tag rid: 'SV-207467r854640_rule'
  tag stig_id: 'SRG-OS-000360-VMM-001370'
  tag gtitle: 'SRG-OS-000360'
  tag fix_id: 'F-7724r365806_fix'
  tag 'documentable'
  tag legacy: ['SV-71395', 'V-57135']
  tag cci: ['CCI-000366', 'CCI-001896']
  tag nist: ['CM-6 b', 'AU-9 (5)']
end
