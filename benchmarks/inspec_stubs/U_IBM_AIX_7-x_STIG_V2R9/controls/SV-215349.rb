control 'SV-215349' do
  title 'If AIX system does not act as a remote print server for other servers, the lpd daemon must be disabled.'
  desc 'The lpd daemon accepts remote print jobs from other systems.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command:
# lsitab lpd

If the command yields any output, this is a finding.'
  desc 'fix', 'In "/etc/inittab", remove the "lpd" entry by running the following command:
# rmitab lpd

To request the init command to re-examine the "/etc/inittab" file, enter: 
# telinit q'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16547r294498_chk'
  tag severity: 'medium'
  tag gid: 'V-215349'
  tag rid: 'SV-215349r508663_rule'
  tag stig_id: 'AIX7-00-003043'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16545r294499_fix'
  tag 'documentable'
  tag legacy: ['SV-101421', 'V-91323']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
