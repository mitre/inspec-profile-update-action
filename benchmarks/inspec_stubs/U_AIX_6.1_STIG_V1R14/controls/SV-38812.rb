control 'SV-38812' do
  title 'The ftpusers file must not have an extended ACL.'
  desc 'Excessive permissions on the ftpusers file could permit unauthorized modification.  Unauthorized modification could result in Denial of Service to authorized FTP users or permit unauthorized users to access the FTP service.'
  desc 'check', 'Check the permissions of the /etc/ftpusers file.
#aclget /etc/ftpusers 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the ftpusers file and disable extended permissions. 

#acledit /etc/ftpusers'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37052r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22445'
  tag rid: 'SV-38812r1_rule'
  tag stig_id: 'GEN004950'
  tag gtitle: 'GEN004950'
  tag fix_id: 'F-32319r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
