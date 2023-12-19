control 'SV-26431' do
  title 'The /etc/group file must be owned by root.'
  desc 'The /etc/group file is critical to system security and must be owned by a privileged user.  The group file contains a list of system groups and associated information.'
  desc 'fix', 'Change the owner of the /etc/group file to root.

# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22335'
  tag rid: 'SV-26431r1_rule'
  tag stig_id: 'GEN001391'
  tag gtitle: 'GEN001391'
  tag fix_id: 'F-23621r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
