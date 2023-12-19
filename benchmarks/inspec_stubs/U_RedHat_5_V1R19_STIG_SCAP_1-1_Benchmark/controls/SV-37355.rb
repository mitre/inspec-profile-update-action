control 'SV-37355' do
  title "The root account's home directory (other than /) must have mode 0700."
  desc 'Permissions greater than 0700 could allow unauthorized users access to the root home directory.'
  desc 'fix', 'The root home directory will be configured to have permission set of 0700 or less permissive. Do not change the protections of the / directory. Use the following command to change protections for the root home directory: 
# chmod 0700 /rootdir.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-775'
  tag rid: 'SV-37355r3_rule'
  tag stig_id: 'GEN000920'
  tag gtitle: 'GEN000920'
  tag fix_id: 'F-31288r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
