control 'SV-228402' do
  title 'Exchange software must be monitored for unauthorized changes.'
  desc 'Monitoring software files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine whether the site monitors system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis. 

If software files are not monitored for unauthorized changes, this is a finding.

Note: A properly configured HBSS Policy Auditor File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. The Asset module within HBSS does not meet this requirement.'
  desc 'fix', 'Update the EDSP to specify that the organization monitors system files on servers for unauthorized changes against a baseline on a weekly basis or verify that this information is documented by the organization.

Monitor the software files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on Exchange servers for unauthorized changes against a baseline on a weekly basis. 

Note: This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30635r497002_chk'
  tag severity: 'medium'
  tag gid: 'V-228402'
  tag rid: 'SV-228402r612748_rule'
  tag stig_id: 'EX16-MB-000590'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-30620r497003_fix'
  tag 'documentable'
  tag legacy: ['SV-95441', 'V-80731']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
