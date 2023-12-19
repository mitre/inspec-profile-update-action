control 'SV-226626' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', '# ls -lL /var/cron/log
If this file does not exist, or is older than the last cron job, this is a finding.
# more /etc/default/cron
If a CRONLOG=YES line does not exist, this is a finding.'
  desc 'fix', 'Edit /etc/default/cron and set CRONLOG=YES.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28787r483290_chk'
  tag severity: 'medium'
  tag gid: 'V-226626'
  tag rid: 'SV-226626r603265_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-28775r483291_fix'
  tag 'documentable'
  tag legacy: ['SV-27349', 'V-982']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
