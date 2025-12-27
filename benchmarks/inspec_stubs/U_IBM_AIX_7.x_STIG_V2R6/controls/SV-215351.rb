control 'SV-215351' do
  title 'If there are no X11 clients that require CDE on AIX, the dt service must be disabled.'
  desc 'This entry executes the CDE startup script which starts the AIX Common Desktop Environment.

To prevent attacks this daemon should not be enabled unless there is no alternative.'
  desc 'check', 'From the command prompt, execute the following command:
# lsitab dt

If the command yields any output, this is a finding.'
  desc 'fix', 'In "/etc/inittab", remove the "dt" entry by running the following command:
# rmitab dt

To request the init command to re-examine the "/etc/inittab" file, enter: 
# telinit q'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16549r294504_chk'
  tag severity: 'medium'
  tag gid: 'V-215351'
  tag rid: 'SV-215351r508663_rule'
  tag stig_id: 'AIX7-00-003045'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16547r294505_fix'
  tag 'documentable'
  tag legacy: ['SV-101425', 'V-91327']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
