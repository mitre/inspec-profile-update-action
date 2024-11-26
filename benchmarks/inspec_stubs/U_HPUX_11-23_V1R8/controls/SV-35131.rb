control 'SV-35131' do
  title 'The rlogind service must not be installed.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service. SSH should be used in place of this service.'
  desc 'check', %q(Determine if the rlogind service is installed. 
# cat /etc/inetd.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[  \t]*//'  | grep -v "^#"  | grep -c rlogind

If rlogind is found to be installed, this is a finding.)
  desc 'fix', 'Edit /etc/inetd.conf and comment out the rlogind service:
# vi  /etc/inetd.conf

Restart the inetd service via the following command:
# inetd -c

Disable the rlogind binary:
chmod 000 /usr/lbin/rlogind

Additionally, the binary name may also be changed:
mv /usr/lbin/rlogind /usr/lbin/<new_binary_name>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22433'
  tag rid: 'SV-35131r1_rule'
  tag stig_id: 'GEN003835'
  tag gtitle: 'GEN003835'
  tag fix_id: 'F-31903r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
