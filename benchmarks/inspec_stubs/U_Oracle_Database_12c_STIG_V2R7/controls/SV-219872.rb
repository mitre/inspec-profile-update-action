control 'SV-219872' do
  title 'Remote database or other external access must use fully-qualified names.'
  desc 'The Oracle GLOBAL_NAMES parameter is used to set the requirement for database link names to be the same name as the remote database whose connection they define. By using the same name for both, ambiguity is avoided and unauthorized or unintended connections to remote databases are less likely.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'global_names';

If the value returned is FALSE, this is a finding."
  desc 'fix', 'From SQL*Plus:

  alter system set global_names = TRUE scope = spfile;

Note: This parameter, if changed, will affect all currently defined Oracle database links.

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21583r533128_chk'
  tag severity: 'medium'
  tag gid: 'V-219872'
  tag rid: 'SV-219872r879887_rule'
  tag stig_id: 'O121-BP-026300'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21582r533129_fix'
  tag 'documentable'
  tag legacy: ['SV-76019', 'V-61529']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
