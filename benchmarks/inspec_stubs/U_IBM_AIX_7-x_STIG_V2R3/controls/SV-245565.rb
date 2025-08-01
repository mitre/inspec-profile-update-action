control 'SV-245565' do
  title 'The AIX /etc/inetd.conf file must have a mode of 0640 or less permissive.'
  desc "Failure to set proper permissions of sensitive files or utilities may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of "/etc/inetd.conf": 
# ls -al /etc/inetd.conf

The above command should yield the following output:
-rw-r----- root system /etc/inetd.conf

If the file has a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Change the ownership of the file to root using command: 
# chmod 0640 /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48844r755134_chk'
  tag severity: 'medium'
  tag gid: 'V-245565'
  tag rid: 'SV-245565r755136_rule'
  tag stig_id: 'AIX7-00-002093'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48799r755135_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
