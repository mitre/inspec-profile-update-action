control 'SV-234789' do
  title 'Exchange software must be monitored for unauthorized changes.'
  desc 'Monitoring software files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine whether the site monitors system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis. 

If software files are not monitored for unauthorized changes on a weekly basis, this is a finding.

Note: A properly configured HBSS Policy Auditor File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. The Asset module within HBSS does not meet this requirement.'
  desc 'fix', 'Update the EDSP.

Monitor the software files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on Exchange servers for unauthorized changes against a baseline on a weekly basis. 

Use an approved DoD monitoring tool.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37975r617306_chk'
  tag severity: 'medium'
  tag gid: 'V-234789'
  tag rid: 'SV-234789r617308_rule'
  tag stig_id: 'EX13-CA-000125'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-37938r617307_fix'
  tag 'documentable'
  tag legacy: ['SV-84387', 'V-69765']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
