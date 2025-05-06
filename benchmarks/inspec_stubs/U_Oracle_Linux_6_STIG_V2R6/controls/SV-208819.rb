control 'SV-208819' do
  title 'The /etc/group file must be owned by root.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'To check the ownership of "/etc/group", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.'
  desc 'fix', 'To properly set the owner of "/etc/group", run the command: 

# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9072r357437_chk'
  tag severity: 'medium'
  tag gid: 'V-208819'
  tag rid: 'SV-208819r793604_rule'
  tag stig_id: 'OL6-00-000042'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9072r357438_fix'
  tag 'documentable'
  tag legacy: ['SV-64981', 'V-50775']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
