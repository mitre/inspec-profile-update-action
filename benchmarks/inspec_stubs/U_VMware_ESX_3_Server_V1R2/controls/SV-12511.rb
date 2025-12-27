control 'SV-12511' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and, therefore, presents confidentiality and integrity risks.  FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment.   SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', "Determine if unencrypted ftp or telnet are enabled.
# cat /etc/inetd.conf | tr ‘\\011’ ‘ ‘ | tr –s ‘ ‘ | sed -e 's/^[  \\t]*//'  | grep –v “^#” | \\
egrep –c –i “ i^ftp|ftp| ftp|^telnet|telnet| telnet”

If either of these services are found (IE: the command returns a non-zero value), and are not commented, ask the SA if both of these services are encrypted. If they are not, this is a finding."
  desc 'fix', 'Edit /etc/inetd.conf and comment out or remove the "ftp" and "telnet" services.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7974r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12010'
  tag rid: 'SV-12511r2_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'GEN004800'
  tag fix_id: 'F-11270r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
