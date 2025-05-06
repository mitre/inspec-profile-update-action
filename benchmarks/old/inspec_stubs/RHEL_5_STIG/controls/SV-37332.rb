control 'SV-37332' do
  title 'The /etc/nsswitch.conf file must have mode 0644 or less permissive.'
  desc 'The nsswitch.conf file (or equivalent) configures the source of a variety of system security information including account, group, and host lookups.  Malicious changes could prevent the system from functioning or compromise system security.'
  desc 'fix', 'Change the mode of the /etc/nsswitch.conf file to 0644 or less permissive.
# chmod 0644 /etc/nsswitch.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22329'
  tag rid: 'SV-37332r1_rule'
  tag stig_id: 'GEN001373'
  tag gtitle: 'GEN001373'
  tag fix_id: 'F-31270r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
