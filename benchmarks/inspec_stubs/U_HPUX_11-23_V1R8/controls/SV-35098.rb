control 'SV-35098' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and, therefore, presents confidentiality and integrity risks.  FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment.   SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', %q(Determine if unencrypted FTP is enabled.
# cat /etc/inetd.conf | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' | grep -v "^#" | grep -c -i "^ftp"

If the service is found (i.e., the command returns a non-zero value), and  not commented, ask the SA if this service is encrypted. If  not, this is a finding.)
  desc 'fix', 'Edit /etc/inetd.conf and comment out or remove the ftp  service.

Refresh the inet daemon.
inetd -c'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36579r3_chk'
  tag severity: 'medium'
  tag gid: 'V-12010'
  tag rid: 'SV-35098r1_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'GEN004800'
  tag fix_id: 'F-31947r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
