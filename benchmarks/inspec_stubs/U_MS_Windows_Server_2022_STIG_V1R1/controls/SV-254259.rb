control 'SV-254259' do
  title 'Windows Server 2022 system files must be monitored for unauthorized changes.'
  desc 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Determine whether the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

If system files are not monitored for unauthorized changes, this is a finding.

A properly configured and approved DoD ESS solution that supports a File Integrity Monitor (FIM) module will meet the requirement for file integrity checking.'
  desc 'fix', 'Monitor the system for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis. This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57744r848591_chk'
  tag severity: 'medium'
  tag gid: 'V-254259'
  tag rid: 'SV-254259r848593_rule'
  tag stig_id: 'WN22-00-000220'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-57695r848592_fix'
  tag 'documentable'
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
