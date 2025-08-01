control 'SV-35133' do
  title 'The rexecd service must not be installed.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service. SSH should be used in place of this service.'
  desc 'check', %q(Determine if the rexecd service is installed. 
# cat /etc/inetd.conf | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' |grep -v "^#" | cut -f 6,7 -d " " | grep -c -i rexecd

If rexecd is found to be installed, this is a finding.)
  desc 'fix', 'Edit /etc/inetd.conf and comment out the rexecd service:
# vi  /etc/inetd.conf

Restart the inetd service via the following command:
# inetd -c

Disable the binary:
chmod 000 /usr/lbin/rexecd

Additionally, the binary name may also be changed:
mv /usr/lbin/rexecd /usr/lbin/<new_binary_name>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36541r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22434'
  tag rid: 'SV-35133r1_rule'
  tag stig_id: 'GEN003845'
  tag gtitle: 'GEN003845'
  tag fix_id: 'F-31905r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
