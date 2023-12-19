control 'SV-216107' do
  title 'The default umask for FTP users must be 077.'
  desc 'Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions.'
  desc 'check', %q(The package service/network/ftp must be installed for this check.

# pkg list service/network/ftp

If the output of this command is:

pkg list: no packages matching 'service/network/ftp' installed

no further action is required.

Determine if the FTP umask is set to 077.

# egrep -i "^UMASK" /etc/proftpd.conf | awk '{ print $2 }'

If 077 is not displayed, this is a finding.)
  desc 'fix', "The root role is required.

# pkg list service/network/ftp

If the output of this command is:

pkg list: no packages matching 'service/network/ftp' installed

no further action is required. Otherwise, edit the FTP configuration file.

# pfedit /etc/proftpd.conf

Locate the line containing:

Umask

Change the line to read:

Umask 077"
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17345r372703_chk'
  tag severity: 'low'
  tag gid: 'V-216107'
  tag rid: 'SV-216107r603268_rule'
  tag stig_id: 'SOL-11.1-040260'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17343r372704_fix'
  tag 'documentable'
  tag legacy: ['V-48071', 'SV-60943']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
