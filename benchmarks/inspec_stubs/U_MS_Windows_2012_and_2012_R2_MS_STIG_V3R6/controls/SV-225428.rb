control 'SV-225428' do
  title 'System files must be monitored for unauthorized changes.'
  desc 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Determine whether the site monitors system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis.  

If system files are not monitored for unauthorized changes, this is a finding.

A properly configured McAfee Application Control and Change Control (MACC) module will meet the requirement for file integrity checking.'
  desc 'fix', 'Monitor system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis. This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27127r860011_chk'
  tag severity: 'medium'
  tag gid: 'V-225428'
  tag rid: 'SV-225428r860012_rule'
  tag stig_id: 'WN12-GE-000017'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27115r857217_fix'
  tag 'documentable'
  tag legacy: ['SV-52215', 'V-2907']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
