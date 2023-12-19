control 'SV-215343' do
  title 'The AIX hosts.lpd file must not contain a + character.'
  desc "Having the '+' character in the hosts.lpd (or equivalent) file allows all hosts to use local system print resources."
  desc 'check', 'Look for the presence of a print service configuration file by running the following commands: 

# find /etc -name hosts.lpd -print 
# find /etc -name Systems -print 
# find /etc -name printers.conf

If none of the files are found, this is not applicable. 

Otherwise, examine the configuration file by running: 

# more <print service file> | grep "+"
@+hamlet
+lear
@+prospero

If any lines are found that contain only a "+" character, this is a finding.'
  desc 'fix', 'Remove the "+" entries from the "hosts.lpd" (or equivalent) file.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16541r294480_chk'
  tag severity: 'medium'
  tag gid: 'V-215343'
  tag rid: 'SV-215343r508663_rule'
  tag stig_id: 'AIX7-00-003037'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16539r294481_fix'
  tag 'documentable'
  tag legacy: ['SV-101731', 'V-91633']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
