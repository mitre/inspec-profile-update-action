control 'SV-224840' do
  title 'System files must be monitored for unauthorized changes.'
  desc 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Determine whether the system is monitored for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis.

A properly configured and approved DoD ESS solution that supports a File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. 

If system files are not monitored for unauthorized changes, this is a finding.'
  desc 'fix', 'Monitor the system for unauthorized changes to system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) against a baseline on a weekly basis. This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26531r804010_chk'
  tag severity: 'medium'
  tag gid: 'V-224840'
  tag rid: 'SV-224840r804011_rule'
  tag stig_id: 'WN16-00-000240'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-26519r465423_fix'
  tag 'documentable'
  tag legacy: ['SV-87917', 'V-73265']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end
