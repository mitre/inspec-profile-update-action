control 'SV-29723' do
  title 'There is no local policy for reviewing audit logs.'
  desc 'To be of value, audit logs from servers and other critical systems will be reviewed on a daily basis to identify security breaches and potential weaknesses in the security structure.  This can be done with the use of monitoring software or other utilities for this purpose.'
  desc 'check', 'The site will have a policy that requires servers and other critical systems be reviewed on a daily basis to identify possible security breaches and weakness.   This can be accomplished with the use of monitoring software or other utilities for this purpose.'
  desc 'fix', 'Create a site policy that mandates review of audit logs.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-3244r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3491'
  tag rid: 'SV-29723r2_rule'
  tag gtitle: 'Reviewing Audit Logs'
  tag fix_id: 'F-6578r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
