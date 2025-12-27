control 'SV-226518' do
  title 'The /etc/group file must be owned by root.'
  desc 'The /etc/group file is critical to system security and must be owned by a privileged user.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify the /etc/group file is owned by root.

Procedure:
# ls -l /etc/group
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/group file to root.

# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28679r482942_chk'
  tag severity: 'medium'
  tag gid: 'V-226518'
  tag rid: 'SV-226518r603265_rule'
  tag stig_id: 'GEN001391'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28667r482943_fix'
  tag 'documentable'
  tag legacy: ['SV-26431', 'V-22335']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
