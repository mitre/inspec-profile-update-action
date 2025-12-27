control 'SV-248607' do
  title 'The OL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', 'Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo grep -ir GSSAPIAuthentication  /etc/ssh/sshd_config*

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the ISSO, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to not allow GSSAPI authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":

GSSAPIAuthentication no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52041r858575_chk'
  tag severity: 'medium'
  tag gid: 'V-248607'
  tag rid: 'SV-248607r858576_rule'
  tag stig_id: 'OL08-00-010522'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51995r779386_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
