control 'SV-27366' do
  title 'The cron.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the cron.allow file is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or to edit sensitive information.'
  desc 'fix', '# chown root /etc/cron.d/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4361'
  tag rid: 'SV-27366r1_rule'
  tag stig_id: 'GEN003240'
  tag gtitle: 'GEN003240'
  tag fix_id: 'F-24611r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
