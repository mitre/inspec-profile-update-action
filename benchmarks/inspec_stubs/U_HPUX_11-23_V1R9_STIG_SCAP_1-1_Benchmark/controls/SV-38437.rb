control 'SV-38437' do
  title 'The /etc/syslog.conf file must be owned by bin.'
  desc 'If the /etc/syslog.conf file is not owned by bin, unauthorized users could be allowed to view, edit, or delete important system messages handled by the syslog facility.'
  desc 'fix', 'Use the chown command to set the owner to bin.
# chown bin /etc/syslog.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-4393'
  tag rid: 'SV-38437r1_rule'
  tag stig_id: 'GEN005400'
  tag gtitle: 'GEN005400'
  tag fix_id: 'F-31988r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
