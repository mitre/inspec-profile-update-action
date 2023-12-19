control 'SV-37143' do
  title 'The /etc/gshadow file must be owned by root.'
  desc 'The /etc/gshadow file is critical to system security and must be owned by a privileged user.  The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'fix', 'Change the owner of the /etc/gshadow file to root.
# chown root /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22341'
  tag rid: 'SV-37143r1_rule'
  tag stig_id: 'GEN000000-LNX001431'
  tag gtitle: 'GEN000000-LNX001431'
  tag fix_id: 'F-31110r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
