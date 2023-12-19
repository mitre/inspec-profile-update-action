control 'SV-38695' do
  title 'The /etc/netsvc.conf file must be root owned.'
  desc 'The /etc/netsvc.conf file is used to specify the ordering of name resolution for the sendmail command,  alias resolution for the sendmail command, and host name resolution routines.    Malicious changes could prevent the system from functioning correctly or compromise system security.'
  desc 'check', 'Verify the /etc/netsvc.conf file is owned by root. 
# ls -l /etc/netsvc.conf 
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/netsvc.conf file to root. 

# chown root /etc/netsvc.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38419r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29491'
  tag rid: 'SV-38695r1_rule'
  tag stig_id: 'GEN000000-AIX0085'
  tag gtitle: 'GEN000000-AIX0085'
  tag fix_id: 'F-33710r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
