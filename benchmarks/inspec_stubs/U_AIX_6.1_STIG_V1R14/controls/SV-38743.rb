control 'SV-38743' do
  title 'Audio devices must not have extended ACLs.'
  desc 'File system ACLs can provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', 'Determine the audio device files for the system.
Procedure:
# /usr/sbin/lsdev -C | grep -i audio 

#aclget /dev/*aud0 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the audio device file(s) and disable extended permissions.
  
#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37184r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22367'
  tag rid: 'SV-38743r1_rule'
  tag stig_id: 'GEN002330'
  tag gtitle: 'GEN002330'
  tag fix_id: 'F-32460r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
