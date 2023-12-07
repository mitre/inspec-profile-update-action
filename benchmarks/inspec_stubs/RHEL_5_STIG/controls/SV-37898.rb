control 'SV-37898' do
  title 'The system and user default umask must be 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask can be represented as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.  This requirement applies to the globally configured system defaults and the user defaults for each account on the system.'
  desc 'fix', 'Edit local and global initialization files that contain "umask" and change them to use 077 instead of the current value.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-808'
  tag rid: 'SV-37898r2_rule'
  tag stig_id: 'GEN002560'
  tag gtitle: 'GEN002560'
  tag fix_id: 'F-32392r1_fix'
  tag severity_override_guidance: 'If the default umask is 000 or does not restrict the world-writable permission, this becomes a CAT I finding.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
