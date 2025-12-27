control 'SV-215348' do
  title 'The AIX qdaemon must be disabled if local or remote printing is not required.'
  desc 'The qdaemon program is the printing scheduling daemon that manages the submission of print jobs to the piobe service.

To prevent remote attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command:
# lsitab qdaemon

If the command yields any output, this is a finding.'
  desc 'fix', 'In "/etc/inittab", remove the "qdaemon" entry by running the following command:
# rmitab qdaemon

To request the init command to re-examine the "/etc/inittab" file, enter: 
# telinit q'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16546r294495_chk'
  tag severity: 'medium'
  tag gid: 'V-215348'
  tag rid: 'SV-215348r508663_rule'
  tag stig_id: 'AIX7-00-003042'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16544r294496_fix'
  tag 'documentable'
  tag legacy: ['V-91321', 'SV-101419']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
