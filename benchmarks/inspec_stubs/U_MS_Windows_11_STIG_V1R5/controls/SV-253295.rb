control 'SV-253295' do
  title 'Windows 11 nonpersistent VM sessions must not exceed 24 hours.'
  desc 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization must enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.'
  desc 'check', 'Verify there is a documented policy or procedure in place that nonpersistent VM sessions do not exceed 24 hours.                                                                                                                                                                                                                                                                                                  

If the system is NOT a nonpersistent VM, this is Not Applicable. 

For Azure Virtual Desktop (AVD) implementations with no data at rest, this is Not Applicable.

If there is no such documented policy or procedure in place, this is a finding.'
  desc 'fix', 'Set nonpersistent VM sessions to not exceed 24 hours.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56748r890450_chk'
  tag severity: 'medium'
  tag gid: 'V-253295'
  tag rid: 'SV-253295r890452_rule'
  tag stig_id: 'WN11-00-000250'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-56698r890451_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
