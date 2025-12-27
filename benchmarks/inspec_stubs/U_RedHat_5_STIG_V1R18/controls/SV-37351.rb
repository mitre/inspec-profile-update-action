control 'SV-37351' do
  title 'The /etc/group file must be owned by root.'
  desc 'The /etc/group file is critical to system security and must be owned by a privileged user.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify the /etc/group file is owned by root.
# ls -l /etc/group
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/group file to root.
# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36042r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22335'
  tag rid: 'SV-37351r1_rule'
  tag stig_id: 'GEN001391'
  tag gtitle: 'GEN001391'
  tag fix_id: 'F-31286r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
