control 'SV-208821' do
  title 'The /etc/group file must have mode 0644 or less permissive.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'To check the permissions of "/etc/group", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following permissions: "-rw-r--r--" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the permissions of "/etc/group", run the command: 

# chmod 644 /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9074r357443_chk'
  tag severity: 'medium'
  tag gid: 'V-208821'
  tag rid: 'SV-208821r793606_rule'
  tag stig_id: 'OL6-00-000044'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9074r357444_fix'
  tag 'documentable'
  tag legacy: ['SV-64985', 'V-50779']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
