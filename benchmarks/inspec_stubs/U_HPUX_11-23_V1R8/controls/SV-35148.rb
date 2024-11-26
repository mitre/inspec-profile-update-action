control 'SV-35148' do
  title 'The hosts.lpd (or equivalent) must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification. Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Locate any print service configuration file(s) on the system. HP vendor documentation identifies the following names and locations of print service configuration files on the system that can be checked via the following commands:
# ls -lL /var/spool/lp/.rhosts
# ls -lL /var/adm/inetd.sec
# ls -lL /etc/hosts.equiv

If no print service configuration file is found, this is not a finding.

Check the mode of the print service configuration file.
# ls -lL <print service configuration file>

If the mode of the print service configuration file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/hosts.lpd file (or equivalent) to 0644 or less permissive. 

Procedure:
# chmod 0644 <print service configuration file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-829'
  tag rid: 'SV-35148r1_rule'
  tag stig_id: 'GEN003940'
  tag gtitle: 'GEN003940'
  tag fix_id: 'F-30299r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
