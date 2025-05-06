control 'SV-827' do
  title 'The hosts.lpd file (or equivalent) must not contain a "+" character.'
  desc 'Having the "+" character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources.'
  desc 'check', 'Look for the presence of a print service configuration file.

Procedure:
# find /etc -name hosts.lpd -print
# find /etc -name Systems -print  
# find /etc -name printers.conf

If none of the files are found, this check is not applicable.  

Otherwise, examine the configuration file.

Procedure:
# more <print service file>

Check for entries that contain a "+" or "_" character.  If any are found, this is a finding.'
  desc 'fix', 'Remove the "+" entries from the hosts.lpd (or equivalent) file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-611r2_chk'
  tag severity: 'medium'
  tag gid: 'V-827'
  tag rid: 'SV-827r2_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'GEN003900'
  tag fix_id: 'F-981r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
