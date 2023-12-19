control 'SV-24902' do
  title 'The Oracle OS_AUTHENT_PREFIX parameter should be changed from the default value of OPS$.'
  desc 'The OS_AUTHENT_PREFIX parameter defines the prefix for database account names to be identified EXTERNALLY by the operating system. When set to the special value of OPS$, accounts defined with the prefix of OPS$ may authenticate either with a password or with OS authentication. Use of more than one authentication method to access a single account results in a loss of accountability, that is, it is similar to a shared account. Setting this parameter to a value other than OPS$ prevents a shared usage of a single account.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'os_authent_prefix';

If the value returned is OPS$ or ops$, this is a Finding."
  desc 'fix', "Specify an operating system authenticated username prefix other than OPS$.    

From SQL*Plus:

  alter system set os_authent_prefix = [prefix value] scope = spfile;

Compliant selections for [prefix value] are:
  a null string ('')
  a text value other than 'OPS$'

The above SQL*Plus command will set the parameter to take effect at next system startup."
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29461r2_chk'
  tag severity: 'low'
  tag gid: 'V-2531'
  tag rid: 'SV-24902r2_rule'
  tag stig_id: 'DO3447-ORACLE11'
  tag gtitle: 'Oracle OS_AUTHENT_PREFIX parameter'
  tag fix_id: 'F-26523r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
