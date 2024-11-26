control 'SV-37714' do
  title 'The /etc/news/readers.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the readers.conf file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'fix', 'Change the mode of the /etc/news/readers.conf file to 0600.
# chmod 0600 /etc/news/readers.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4275'
  tag rid: 'SV-37714r1_rule'
  tag stig_id: 'GEN006300'
  tag gtitle: 'GEN006300'
  tag fix_id: 'F-32155r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
