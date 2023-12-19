control 'SV-38337' do
  title 'The /etc/group file must be owned by bin.'
  desc 'The /etc/group file is critical to system security and must be owned by a privileged user.  The group file contains a list of system groups and associated information.'
  desc 'fix', 'Change the owner of the /etc/group file to bin.
# chown bin /etc/group'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22335'
  tag rid: 'SV-38337r1_rule'
  tag stig_id: 'GEN001391'
  tag gtitle: 'GEN001391'
  tag fix_id: 'F-31601r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
