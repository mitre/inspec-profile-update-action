control 'SV-38716' do
  title 'The system must not have the PCNFS service active.'
  desc 'The PCNFS service predates Microsoft’s SMB specifications.   If a similar service is needed to share files from a Windows based OS to a UNIX based OS,  consider SAMBA.'
  desc 'check', 'Check the /etc/inetd.conf file for active PCNFS service.

#grep pcnfsd /etc/inetd.conf | grep -v \\#

If the PCNFS service is enabled,  this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the PCNFS service line. Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37812r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29512'
  tag rid: 'SV-38716r1_rule'
  tag stig_id: 'GEN009280'
  tag gtitle: 'GEN009280'
  tag fix_id: 'F-33070r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
