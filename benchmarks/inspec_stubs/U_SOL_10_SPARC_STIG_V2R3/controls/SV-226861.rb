control 'SV-226861' do
  title 'The at.deny file must not be empty if it exists.'
  desc 'On some systems, if there is no at.allow file and there is an empty at.deny file, then the system assumes everyone has permission to use the at facility.  This could create an insecure setting in the case of malicious users or system intruders.'
  desc 'check', '# more /etc/cron.d/at.deny
If the at.deny file exists and is empty, this is a finding.'
  desc 'fix', 'Add appropriate users to the at.deny file, or remove the empty at.deny file if an at.allow file exists.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29023r484867_chk'
  tag severity: 'medium'
  tag gid: 'V-226861'
  tag rid: 'SV-226861r603265_rule'
  tag stig_id: 'GEN003300'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29011r484868_fix'
  tag 'documentable'
  tag legacy: ['V-985', 'SV-27380']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
