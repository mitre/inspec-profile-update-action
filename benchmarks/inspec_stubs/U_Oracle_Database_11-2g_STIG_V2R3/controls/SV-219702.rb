control 'SV-219702' do
  title 'The Oracle REMOTE_OS_AUTHENT parameter must be set to FALSE.'
  desc 'Setting this value to TRUE allows operating system authentication over an unsecured connection. Trusting remote operating systems can allow a user to impersonate another operating system user and connect to the database without having to supply a password. If REMOTE_OS_AUTHENT is set to true, the only information a remote user needs to connect to the database is the name of any user whose account is setup to be authenticated by the operating system.'
  desc 'check', "From SQL*Plus:

select value from v$parameter where name = 'remote_os_authent';

If the value returned does not equal FALSE, this is a Finding."
  desc 'fix', 'Document remote OS authentication in the System Security Plan.

If not required or not mitigated to an acceptable level, disable remote OS authentication.

From SQL*Plus:

alter system set remote_os_authent = FALSE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.7
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21427r306955_chk'
  tag severity: 'high'
  tag gid: 'V-219702'
  tag rid: 'SV-219702r401224_rule'
  tag stig_id: 'O112-BP-021900'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21426r306956_fix'
  tag 'documentable'
  tag legacy: ['SV-68215', 'V-53975']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
