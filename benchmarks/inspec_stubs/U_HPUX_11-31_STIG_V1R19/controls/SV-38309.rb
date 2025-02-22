control 'SV-38309' do
  title 'System log files must not have extended ACLs, except as needed to support authorized software.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value. Authorized software may be given log file access through the use of extended ACLs when needed and configured to provide the least privileges required.'
  desc 'check', 'Verify all system log files have no extended ACLs.

# ls -lL /var/log /var/log/syslog /var/adm /var/opt

If the permissions include a "+" the file has an extended ACL. If an extended ACL exists, verify with the SA if the ACL is required to support authorized software and provides the minimum necessary permissions. If an extended ACL exists providing access beyond the needs of authorized software, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.

# chacl -z /var/adm/*'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36314r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22315'
  tag rid: 'SV-38309r1_rule'
  tag stig_id: 'GEN001270'
  tag gtitle: 'GEN001270'
  tag fix_id: 'F-31569r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
