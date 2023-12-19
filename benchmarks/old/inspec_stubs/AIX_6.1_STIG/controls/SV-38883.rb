control 'SV-38883' do
  title 'The hosts.lpd file (or equivalent) must not contain a "+" character.'
  desc 'Having the "+" character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources.'
  desc 'check', 'Look for the presence of a print service configuration file.

Procedure:
# find /etc -name hosts.lpd -print
# find /etc -name Systems -print 
# find /etc -name printers.conf

If none of the files are found, this check should be marked not applicable. 

Otherwise, examine the configuration file.

Procedure:
# more <print service file>

Check for entries containing a "+" character by itself on any line. If any are found, this is a finding.'
  desc 'fix', 'Remove the "+" entries from the hosts.lpd (or equivalent) file.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-827'
  tag rid: 'SV-38883r1_rule'
  tag stig_id: 'GEN003900'
  tag gtitle: 'GEN003900'
  tag fix_id: 'F-33132r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
