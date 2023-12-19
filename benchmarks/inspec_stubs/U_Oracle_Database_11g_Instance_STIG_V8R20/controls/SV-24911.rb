control 'SV-24911' do
  title 'The Oracle REMOTE_OS_AUTHENT parameter should be set to FALSE.'
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
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29467r2_chk'
  tag severity: 'high'
  tag gid: 'V-2554'
  tag rid: 'SV-24911r2_rule'
  tag stig_id: 'DO3538-ORACLE11'
  tag gtitle: 'Oracle REMOTE_OS_AUTHENT parameter'
  tag fix_id: 'F-26531r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This finding may be downgraded to a Category II severity code if the following mitigations have been implemented:  1)  A logon trigger verifies that any connections to accounts identified externally come from a single, specific IP address and kills the connection if determined otherwise, and 2)  To help prevent access by a spoofed IP address, the single connecting system and the database host are isolated behind a firewall with either Network Address Translation (NAT) implemented and/or the firewall is configured to reject connections from the single source IP address originating outside the isolated segment.'
  tag responsibility: 'Database Administrator'
end
