control 'SV-35118' do
  title 'The /etc/news/nnrp.access (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check nnrp.access permissions.
# find / -type f -name nnrp.access | xargs -n1 ls -lL

If nnrp.access has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the nnrp.access file to 0600.

# chmod 0600 <path>/nnrp.access'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4275'
  tag rid: 'SV-35118r1_rule'
  tag stig_id: 'GEN006300'
  tag gtitle: 'GEN006300'
  tag fix_id: 'F-30266r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
