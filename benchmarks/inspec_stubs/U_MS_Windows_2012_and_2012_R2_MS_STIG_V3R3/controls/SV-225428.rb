control 'SV-225428' do
  title 'System files must be monitored for unauthorized changes.'
  desc 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Determine whether the site monitors system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis.  If system files are not monitored for unauthorized changes, this is a finding.

A properly configured and approved DoD ESS solution that supports a File Integrity Monitor (FIM) module will meet the requirement for file integrity checking.'
  desc 'fix', 'Monitor system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis.  This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27127r793240_chk'
  tag severity: 'medium'
  tag gid: 'V-225428'
  tag rid: 'SV-225428r793241_rule'
  tag stig_id: 'WN12-GE-000017'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27115r471627_fix'
  tag 'documentable'
  tag legacy: ['SV-52215', 'V-2907']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
