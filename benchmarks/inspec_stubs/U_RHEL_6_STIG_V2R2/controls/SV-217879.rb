control 'SV-217879' do
  title 'The /etc/passwd file must have mode 0644 or less permissive.'
  desc 'If the "/etc/passwd" file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.'
  desc 'check', 'To check the permissions of "/etc/passwd", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following permissions: "-rw-r--r--" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the permissions of "/etc/passwd", run the command: 

# chmod 0644 /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19360r376652_chk'
  tag severity: 'medium'
  tag gid: 'V-217879'
  tag rid: 'SV-217879r603264_rule'
  tag stig_id: 'RHEL-06-000041'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19358r376653_fix'
  tag 'documentable'
  tag legacy: ['V-38457', 'SV-50257']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
