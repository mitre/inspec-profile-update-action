control 'SV-38687' do
  title 'System log files must not have extended ACLs, except as needed to support authorized software.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value. Authorized software may be given log file access through the use of extended ACLs when needed and configured to provide the least privileges required.'
  desc 'check', 'Determine if any system log file has an extended ACL. If an extended ACL exists, verify with the SA if the ACL is required to support authorized software and provides the minimum necessary permissions. If an extended ACL exists that provides access beyond the needs of authorized software, this is a finding.

Check to see if extended permissions are disabled.
#aclget <directory>/<file>'
  desc 'fix', 'Remove the extended ACL(s) from the system log file(s) and disable extended permissions.
 
# acledit < directory >/< file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36960r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22315'
  tag rid: 'SV-38687r1_rule'
  tag stig_id: 'GEN001270'
  tag gtitle: 'GEN001270'
  tag fix_id: 'F-32225r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
