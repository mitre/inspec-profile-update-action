control 'SV-252944' do
  title 'The TOSS SSH daemon must not allow Kerberos authentication, except to fulfill documented and validated mission requirements.'
  desc 'Configuring these settings for the SSH daemon provides additional assurance that remote logon via SSH will not use unused methods of authentication, even in the event of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow Kerberos authentication with the following command:

$ sudo grep -i KerberosAuthentication  /etc/ssh/sshd_config

KerberosAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow Kerberos authentication.

Add the following line in "/etc/ssh/sshd_config" or uncomment the line and set the value to "no":

KerberosAuthentication no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56397r824154_chk'
  tag severity: 'medium'
  tag gid: 'V-252944'
  tag rid: 'SV-252944r824156_rule'
  tag stig_id: 'TOSS-04-010420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56347r824155_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
