control 'SV-209049' do
  title 'There must be no .netrc files on the system.'
  desc 'Unencrypted passwords for remote FTP servers may be stored in ".netrc" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.'
  desc 'check', 'To check the system for the existence of any ".netrc" files, run the following command:

$ sudo find /root /home -xdev -name .netrc

If any .netrc files exist, this is a finding.'
  desc 'fix', %q(The ".netrc" files contain login information used to auto-login into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any ".netrc" files should be removed.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9302r357932_chk'
  tag severity: 'medium'
  tag gid: 'V-209049'
  tag rid: 'SV-209049r603263_rule'
  tag stig_id: 'OL6-00-000347'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-9302r357933_fix'
  tag 'documentable'
  tag legacy: ['V-50643', 'SV-64849']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
