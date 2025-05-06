control 'SV-226860' do
  title 'Access to the at utility must be controlled via the at.allow and/or at.deny file(s).'
  desc 'The at facility selectively allows users to execute jobs at deferred times.  It is usually used for one-time jobs. The at.allow file selectively allows access to the at facility.  If there is no at.allow file, there is no ready documentation of who is allowed to submit at jobs.'
  desc 'check', 'Check for the existence of at.allow and at.deny files.
# ls -lL /etc/cron.d/at.allow
# ls -lL /etc/cron.d/at.deny
If neither file exists, this is a finding.'
  desc 'fix', 'Create at.allow and/or at.deny files containing appropriate lists of users to be allowed or denied access to the "at" daemon.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29022r484864_chk'
  tag severity: 'medium'
  tag gid: 'V-226860'
  tag rid: 'SV-226860r854425_rule'
  tag stig_id: 'GEN003280'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29010r484865_fix'
  tag 'documentable'
  tag legacy: ['SV-27376', 'V-984']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
