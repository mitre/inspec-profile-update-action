control 'SV-45205' do
  title 'The system and user default umask must be 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask can be represented as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.  This requirement applies to the globally configured system defaults and the user defaults for each account on the system.'
  desc 'check', 'Check global initialization files for the configured umask value.
Procedure:
# grep umask /etc/* 

Check local initialization files for the configured umask value.
Procedure: 
# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep umask {} \\;

If the system and user default umask is not 077, this a finding. 

Note: If the default umask is 000 or allows for the creation of world-writable files this becomes a Severity Code I finding.'
  desc 'fix', 'Edit local and global initialization files that contain "umask" and change them to use 077 instead of the current value.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42553r1_chk'
  tag severity: 'medium'
  tag gid: 'V-808'
  tag rid: 'SV-45205r1_rule'
  tag stig_id: 'GEN002560'
  tag gtitle: 'GEN002560'
  tag fix_id: 'F-38601r1_fix'
  tag severity_override_guidance: 'If the default umask is 000 or does not restrict the world-writable permission, this becomes a CAT I finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
