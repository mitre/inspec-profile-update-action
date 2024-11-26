control 'SV-218077' do
  title 'The system default umask for daemons must be 027 or 022.'
  desc 'The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions.'
  desc 'check', 'To check the value of the "umask", run the following command: 

$ grep umask /etc/init.d/functions

The output should show either "022" or "027". 
If it does not, this is a finding.'
  desc 'fix', 'The file "/etc/init.d/functions" includes initialization parameters for most or all daemons started at boot time. The default umask of 022 prevents creation of group- or world-writable files. To set the default umask for daemons, edit the following line, inserting 022 or 027 for [UMASK] appropriately: 

umask [UMASK]

Setting the umask to too restrictive a setting can cause serious errors at runtime. Many daemons on the system already individually restrict themselves to a umask of 077 in their own init scripts.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19558r377246_chk'
  tag severity: 'low'
  tag gid: 'V-218077'
  tag rid: 'SV-218077r603264_rule'
  tag stig_id: 'RHEL-06-000346'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19556r377247_fix'
  tag 'documentable'
  tag legacy: ['SV-50443', 'V-38642']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
