control 'SV-828' do
  title 'The hosts.lpd (or equivalent) file must be owned by root, bin, sys, or lp.'
  desc 'Failure to give ownership of the hosts.lpd file to root, bin, sys, or lp provides the designated owner, and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Locate any print service configuration file on the system.  Consult vendor documentation to verify the names and locations of print service configuration files on the system.

Procedure:
# find /etc -name hosts.lpd -print
# find /etc -name Systems -print  

If no print service configuration file is found, this is not applicable.

Check the ownership of the print service configuration file(s).

Procedure:
# ls -lL <print service file>

If the owner of the file is not root, sys, bin, or lp, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/hosts.lpd file (or equivalent, such as /etc/lp/Systems) to root, lp, or another privileged UID.  Consult vendor documentation to determine the name and location of print service configuration files.

Procedure:
# chown root /etc/hosts.lpd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-612r2_chk'
  tag severity: 'medium'
  tag gid: 'V-828'
  tag rid: 'SV-828r2_rule'
  tag stig_id: 'GEN003920'
  tag gtitle: 'GEN003920'
  tag fix_id: 'F-982r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
