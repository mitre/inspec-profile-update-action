control 'SV-38805' do
  title 'The inetd.conf and xinetd.conf files must not have extended ACLs.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the inetd configuration file.
#aclget /etc/inetd.conf 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/inetd.conf file and disable extended permissions. 

#acledit /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22424'
  tag rid: 'SV-38805r1_rule'
  tag stig_id: 'GEN003745'
  tag gtitle: 'GEN003745'
  tag fix_id: 'F-31824r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
