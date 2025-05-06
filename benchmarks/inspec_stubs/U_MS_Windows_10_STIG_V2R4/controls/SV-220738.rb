control 'SV-220738' do
  title 'Windows 10 non-persistent VM sessions should not exceed 24 hours.'
  desc 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization should enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.'
  desc 'check', 'Ensure there is a documented policy or procedure in place that non-persistent VM sessions do not exceed 24 hours.

If there is no such documented policy or procedure in place, this is a finding.'
  desc 'fix', 'Set non-persistent VM sessions to not exceed 24 hours.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22453r554699_chk'
  tag severity: 'medium'
  tag gid: 'V-220738'
  tag rid: 'SV-220738r569187_rule'
  tag stig_id: 'WN10-00-000250'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-22442r554700_fix'
  tag 'documentable'
  tag legacy: ['V-102611', 'SV-111557']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
