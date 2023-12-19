control 'SV-215350' do
  title 'If AIX system does not support either local or remote printing, the piobe service must be disabled.'
  desc 'The piobe daemon is the I/O back end for the printing process, handling the job scheduling and spooling.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command:
# lsitab piobe

If the command yields any output, this is a finding.'
  desc 'fix', 'In "/etc/inittab", remove the "piobe" entry by running the following command:
# rmitab piobe

To request the init command to re-examine the "/etc/inittab" file, enter: 
# telinit q'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16548r294501_chk'
  tag severity: 'medium'
  tag gid: 'V-215350'
  tag rid: 'SV-215350r508663_rule'
  tag stig_id: 'AIX7-00-003044'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16546r294502_fix'
  tag 'documentable'
  tag legacy: ['SV-101423', 'V-91325']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
