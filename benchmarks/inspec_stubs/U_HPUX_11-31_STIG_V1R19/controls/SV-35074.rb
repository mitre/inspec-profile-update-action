control 'SV-35074' do
  title 'The xinetd.d directory must have mode 0755 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'check', 'Check the (x)inetd.conf file for any included directories.

# find / -type f -name xinetd.conf | xargs -n1 ls -lL
# cat <PATH>/xinetd.conf | grep -v "^#" | grep includedir 

If (x)inetd.conf does not exist, or there is no includedir stanza, this is not a finding.

Individually check the mode of any directories in the configuration file.
# ls -lLd <included directories>

If any of the included directories has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of included xinetd configuration 
directories to 0755.
# chmod 0755 <directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36527r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22425'
  tag rid: 'SV-35074r1_rule'
  tag stig_id: 'GEN003750'
  tag gtitle: 'GEN003750'
  tag fix_id: 'F-31888r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
