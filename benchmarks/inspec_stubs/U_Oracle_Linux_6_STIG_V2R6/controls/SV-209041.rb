control 'SV-209041' do
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc 'To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log.'
  desc 'check', 'Verify the "vsftpd" package is installed:

# rpm -qa | grep -i vsftpd
vsftpd-3.0.2-22.e16.x86_64

If the "vsftpd" package is not installed, this is Not Applicable.

Find if logging is applied to the ftp daemon. 

Procedures: 

If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file. 

# grep vsftpd /etc/xinetd.d/*

# grep server_args [vsftpd xinetd.d startup file]

This will indicate the vsftpd config file used when starting through xinetd. If the [server_args]line is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) is used. 

# grep xferlog_enable [vsftpd config file]

If xferlog_enable is missing, or is not set to yes, this is a finding.'
  desc 'fix', 'Add or correct the following configuration options within the "vsftpd" configuration file, located at "/etc/vsftpd/vsftpd.conf". 

xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9294r357908_chk'
  tag severity: 'low'
  tag gid: 'V-209041'
  tag rid: 'SV-209041r793762_rule'
  tag stig_id: 'OL6-00-000339'
  tag gtitle: 'SRG-OS-000037'
  tag fix_id: 'F-9294r357909_fix'
  tag 'documentable'
  tag legacy: ['V-50739', 'SV-64945']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
