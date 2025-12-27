control 'SV-37170' do
  title 'The /etc/gshadow file must have mode 0400.'
  desc 'The /etc/gshadow file is critical to system security and must be protected from unauthorized modification.   The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'fix', 'Change the mode of the /etc/gshadow file to 0400 or less permissive.
# chmod 0400 /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22343'
  tag rid: 'SV-37170r1_rule'
  tag stig_id: 'GEN000000-LNX001433'
  tag gtitle: 'GEN000000-LNX001433'
  tag fix_id: 'F-31130r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
