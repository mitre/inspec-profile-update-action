control 'SV-27377' do
  title 'Access to the at utility must be controlled via the at.allow and/or at.deny file(s).'
  desc 'The at facility selectively allows users to execute jobs at deferred times.  It is usually used for one-time jobs. The at.allow file selectively allows access to the at facility.  If there is no at.allow file, there is no ready documentation of who is allowed to submit at jobs.'
  desc 'fix', 'Create at.allow and/or at.deny files containing appropriate lists of users to be allowed or denied access to the "at" daemon.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-984'
  tag rid: 'SV-27377r1_rule'
  tag stig_id: 'GEN003280'
  tag gtitle: 'GEN003280'
  tag fix_id: 'F-11346r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
