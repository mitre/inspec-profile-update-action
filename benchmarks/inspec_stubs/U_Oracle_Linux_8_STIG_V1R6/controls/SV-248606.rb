control 'SV-248606' do
  title 'The OL 8 SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow Kerberos authentication with the following command:

$ sudo grep -ir "KerberosAuthentication" /etc/ssh/sshd_config*

KerberosAuthentication no

If the value is returned as "yes", the returned line is commented out, or no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow Kerberos authentication. 
 
Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no": 
 
KerberosAuthentication no
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52040r858573_chk'
  tag severity: 'medium'
  tag gid: 'V-248606'
  tag rid: 'SV-248606r858574_rule'
  tag stig_id: 'OL08-00-010521'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51994r779383_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
