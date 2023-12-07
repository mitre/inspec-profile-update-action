control 'SV-37334' do
  title 'The /etc/nsswitch.conf file must not have an extended ACL.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22330'
  tag rid: 'SV-37334r1_rule'
  tag stig_id: 'GEN001374'
  tag gtitle: 'GEN001374'
  tag fix_id: 'F-23607r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
