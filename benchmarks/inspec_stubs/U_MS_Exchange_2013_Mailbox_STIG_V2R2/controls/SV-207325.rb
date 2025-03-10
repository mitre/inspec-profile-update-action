control 'SV-207325' do
  title 'Exchange software must be monitored for unauthorized changes.'
  desc 'Monitoring software files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine whether the site monitors system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis. 

If software files are not monitored for unauthorized changes, this is a finding.

Note: A properly configured HBSS Policy Auditor File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. The Asset module within HBSS does not meet this requirement.'
  desc 'fix', 'Update the EDSP.

Monitor the software files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on Exchange servers for unauthorized changes against a baseline on a weekly basis. 

Note: This can be done with the use of various monitoring tools.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7583r393488_chk'
  tag severity: 'medium'
  tag gid: 'V-207325'
  tag rid: 'SV-207325r615936_rule'
  tag stig_id: 'EX13-MB-000295'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-7583r393489_fix'
  tag 'documentable'
  tag legacy: ['SV-84693', 'V-70071']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
