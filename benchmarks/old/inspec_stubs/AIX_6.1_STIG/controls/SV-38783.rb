control 'SV-38783' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', '#aclget /var/adm/cron/log 
Verify if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the cronlog file and disable extended permissions.

#acledit /var/adm/cron/log'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37250r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22388'
  tag rid: 'SV-38783r1_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'GEN003190'
  tag fix_id: 'F-32475r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
