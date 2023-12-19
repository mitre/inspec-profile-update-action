control 'SV-38697' do
  title 'The /etc/netsvc.conf file must have mode 0644 or less permissive.'
  desc 'The /etc/netsvc.conf file is used to specify the ordering of name resolution for the sendmail command,  alias resolution for the sendmail command, and host name resolution routines.    Malicious changes could prevent the system from functioning correctly or compromise system security.'
  desc 'fix', 'Change the mode of the /etc/netsvc.conf file to 0644 or less permissive.
# chmod 0644 /etc/netsvc.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29493'
  tag rid: 'SV-38697r1_rule'
  tag stig_id: 'GEN000000-AIX0100'
  tag gtitle: 'GEN000000-AIX0100'
  tag fix_id: 'F-33051r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
