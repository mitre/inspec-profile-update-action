control 'SV-227035' do
  title 'The /etc/news/nnrp.access (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the nnrp.access file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check /etc/news/nnrp.access permissions.

# ls -lL /etc/news/nnrp.access

If /etc/news/nnrp.access has a mode more permissive than 0600,  this is a finding.'
  desc 'fix', 'Change the mode of the /etc/news/nnrp.access file to 0600.
# chmod 0600 /etc/news/nnrp.access'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29197r485459_chk'
  tag severity: 'medium'
  tag gid: 'V-227035'
  tag rid: 'SV-227035r603265_rule'
  tag stig_id: 'GEN006300'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29185r485460_fix'
  tag 'documentable'
  tag legacy: ['V-4275', 'SV-4275']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
