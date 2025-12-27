control 'SV-38696' do
  title 'The /etc/netsvc.conf file must be group-owned by bin, sys, or system.'
  desc 'The /etc/netsvc.conf file is used to specify the ordering of name resolution for the sendmail command,  alias resolution for the sendmail command, and host name resolution routines.    Malicious changes could prevent the system from functioning correctly or compromise system security.'
  desc 'check', 'Check the group ownership of the /etc/netcsvc.conf file.

Procedure:
# ls -lL /etc/netsvc.conf

If the file is not group-owned by bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/netsvc.conf file to bin, sys, or system.

Procedure:
# chgrp system /etc/netsvc.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37792r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29492'
  tag rid: 'SV-38696r1_rule'
  tag stig_id: 'GEN000000-AIX0090'
  tag gtitle: 'GEN000000-AIX0090'
  tag fix_id: 'F-33050r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
