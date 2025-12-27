control 'SV-38813' do
  title 'All FTP users must have a default umask of 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask is stored as a 4-digit number, the first digit representing special access modes is typically ignored or required to be zero (0).'
  desc 'check', 'Check the umask setting for the "ftp" user.

Procedure:
# lsuser -a umask ftp

If the umask value does not return 077 or 77, this is a finding.

Check the default umask that the ftpd daemon is running with
# grep ftpd /etc/inetd.conf
If there is not a -u077 argument on the ftpd, this is a finding.'
  desc 'fix', 'Add the arguments -u077 to the ftpd on the /etc/inetd.conf and refresh inetd.
#vi /etc/inetd.conf
#refresh -s inetd

Change the umask of the ftp user.
#chuser umask=077 ftp'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37053r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12011'
  tag rid: 'SV-38813r1_rule'
  tag stig_id: 'GEN005040'
  tag gtitle: 'GEN005040'
  tag fix_id: 'F-32321r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
