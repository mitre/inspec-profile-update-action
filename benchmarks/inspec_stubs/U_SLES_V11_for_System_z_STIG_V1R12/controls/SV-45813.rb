control 'SV-45813' do
  title 'The hosts.lpd (or equivalent) file must be owned by root, bin, sys, or lp.'
  desc 'Failure to give ownership of the hosts.lpd file to root, bin, sys, or lp provides the designated owner, and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the ownership of the print service configuration file.

Procedure:
# find /etc -name hosts.lpd -print
# find /etc -name Systems –print
# find /etc –name printers.conf -print  

If no print service configuration file is found, this is not applicable.

Check the ownership of the print service configuration file(s).

# ls –lL <print service file>

If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/hosts.lpd (or equivalent, such as /etc/lp/Systems) to root.

Procedure:
# chown root <print service file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43134r1_chk'
  tag severity: 'medium'
  tag gid: 'V-828'
  tag rid: 'SV-45813r1_rule'
  tag stig_id: 'GEN003920'
  tag gtitle: 'GEN003920'
  tag fix_id: 'F-39574r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
