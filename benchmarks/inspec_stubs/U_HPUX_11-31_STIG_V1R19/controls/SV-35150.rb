control 'SV-35150' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification. Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Locate any print service configuration file(s) on the system. HP vendor documentation 
identifies the following names and locations of print service configuration files on 
the system that can be checked via the following commands:
# ls -lL /var/spool/lp/.rhosts
# ls -lL /var/adm/inetd.sec
# ls -lL /etc/hosts.equiv

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <print service configuration file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36550r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22436'
  tag rid: 'SV-35150r1_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'GEN003950'
  tag fix_id: 'F-31916r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
