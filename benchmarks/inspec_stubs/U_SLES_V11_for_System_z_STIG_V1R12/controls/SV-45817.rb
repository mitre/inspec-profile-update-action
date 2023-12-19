control 'SV-45817' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', "Check the permissions of the /etc/hosts.lpd (or equivalent) file.
# find /etc -name hosts.lpd -print
# find /etc -name Systems –print
# find /etc -name printers.conf -print  

# ls -lL <print service file>

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <print service file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43138r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22436'
  tag rid: 'SV-45817r1_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'GEN003950'
  tag fix_id: 'F-39205r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
