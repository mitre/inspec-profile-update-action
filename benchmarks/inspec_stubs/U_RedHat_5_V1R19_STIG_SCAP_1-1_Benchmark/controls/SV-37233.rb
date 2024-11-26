control 'SV-37233' do
  title 'System log files must not have extended ACLs, except as needed to support authorized software.'
  desc 'If the system log files are not protected, unauthorized users could change the logged data, eliminating its forensic value.  Authorized software may be given log file access through the use of extended ACLs when needed and configured to provide the least privileges required.'
  desc 'fix', 'Remove the extended ACL from the file.

Procedure:
# setfacl --remove-all [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22315'
  tag rid: 'SV-37233r1_rule'
  tag stig_id: 'GEN001270'
  tag gtitle: 'GEN001270'
  tag fix_id: 'F-31180r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
