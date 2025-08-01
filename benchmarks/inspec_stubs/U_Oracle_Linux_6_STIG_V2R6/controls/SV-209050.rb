control 'SV-209050' do
  title 'The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.'
  desc 'This setting will cause the system greeting banner to be used for FTP connections as well.'
  desc 'check', 'Verify the "vsftpd" package is installed:

# rpm -qa | grep -i vsftpd
vsftpd-3.0.2-22.e16.x86_64

If the "vsftpd" package is not installed, this is Not Applicable.

To verify this configuration, run the following command: 

grep "banner_file" /etc/vsftpd/vsftpd.conf

The output should show the value of "banner_file" is set to "/etc/issue", an example of which is shown below. 

# grep "banner_file" /etc/vsftpd/vsftpd.conf
banner_file=/etc/issue

If it does not, this is a finding.'
  desc 'fix', 'Edit the vsftpd configuration file, which resides at "/etc/vsftpd/vsftpd.conf" by default.

Add or correct the following configuration options. 

banner_file=/etc/issue

Restart the vsftpd daemon.

# service vsftpd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9303r357935_chk'
  tag severity: 'medium'
  tag gid: 'V-209050'
  tag rid: 'SV-209050r793771_rule'
  tag stig_id: 'OL6-00-000348'
  tag gtitle: 'SRG-OS-000023'
  tag fix_id: 'F-9303r357936_fix'
  tag 'documentable'
  tag legacy: ['V-50641', 'SV-64847']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
