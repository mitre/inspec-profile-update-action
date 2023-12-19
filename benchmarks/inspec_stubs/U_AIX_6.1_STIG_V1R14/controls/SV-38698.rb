control 'SV-38698' do
  title 'The /etc/netsvc.conf file must not have an extended ACL.'
  desc 'The /etc/netsvc.conf file is used to specify the ordering of name resolution for the sendmail command,  alias resolution for the sendmail command, and host name resolution routines.    Malicious changes could prevent the system from functioning correctly or compromise system security.'
  desc 'check', 'Verify there is no extended ACL on the  /etc/netsvc.conf file.
# aclget /etc/netsvc.conf 
If extended permissions are enabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/nsswitch.conf file and disable extended permissions.   

#acledit /etc/netsvc.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37794r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29494'
  tag rid: 'SV-38698r1_rule'
  tag stig_id: 'GEN000000-AIX0110'
  tag gtitle: 'GEN000000-AIX0110'
  tag fix_id: 'F-33052r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
