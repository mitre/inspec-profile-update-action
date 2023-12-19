control 'SV-226628' do
  title 'The cron log files must not have extended ACLs.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /var/cron/log
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /var/cron/log'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28789r483296_chk'
  tag severity: 'medium'
  tag gid: 'V-226628'
  tag rid: 'SV-226628r603265_rule'
  tag stig_id: 'GEN003190'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28777r483297_fix'
  tag 'documentable'
  tag legacy: ['SV-26542', 'V-22388']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
