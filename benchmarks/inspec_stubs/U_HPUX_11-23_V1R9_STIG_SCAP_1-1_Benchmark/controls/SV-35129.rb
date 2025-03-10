control 'SV-35129' do
  title 'The remshd service must not be installed.'
  desc 'The remshd process provides a typically unencrypted, host-authenticated remote access service. SSH should be used in place of this service.'
  desc 'fix', 'Uninstall the remshd service from the system.
# cat /etc/inetd.conf | grep -n remshd

Edit the /etc/inetd.conf file and comment the line entry for remshd, 
then reconfigure inetd via:

# inetd -c'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22431'
  tag rid: 'SV-35129r1_rule'
  tag stig_id: 'GEN003825'
  tag gtitle: 'GEN003825'
  tag fix_id: 'F-31900r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
