control 'SV-45816' do
  title 'The hosts.lpd (or equivalent) must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Locate any print service configuration file on the system.  Consult vendor documentation for the name and location of print service configuration files.

Procedure:
# find /etc -name hosts.lpd -print
# find /etc -name Systems –print
# find /etc -name printers.conf -print  


Check the mode of the print service configuration file.

# ls -lL <print service file>


If no print service configuration file is found, this is not applicable.
If the mode of the print service configuration file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/hosts.lpd file (or equivalent, such as /etc/lp/Systems) to 0644 or less permissive.  Consult vendor documentation for the name and location of print service configuration files.

Procedure:
# chmod 0644 <print service file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-829'
  tag rid: 'SV-45816r1_rule'
  tag stig_id: 'GEN003940'
  tag gtitle: 'GEN003940'
  tag fix_id: 'F-39204r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
