control 'SV-35132' do
  title 'The rexec daemon must not be running.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service. SSH should be used in place of this service.'
  desc 'check', %q(# cat /etc/inetd.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  |grep -v "^#" | \
cut -f 6,7 -d " " | grep -c -i rexecd 

If any results are returned, this is a finding.)
  desc 'fix', 'Edit /etc/inetd.conf and comment out the line for the rexec daemon service.   Restart the inetd service via the following command:
# inetd -c'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34990r3_chk'
  tag severity: 'high'
  tag gid: 'V-4688'
  tag rid: 'SV-35132r2_rule'
  tag stig_id: 'GEN003840'
  tag gtitle: 'GEN003840'
  tag fix_id: 'F-30284r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
