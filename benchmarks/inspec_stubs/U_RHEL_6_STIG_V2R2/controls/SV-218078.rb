control 'SV-218078' do
  title 'There must be no .netrc files on the system.'
  desc 'Unencrypted passwords for remote FTP servers may be stored in ".netrc" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.'
  desc 'check', 'To check the system for the existence of any ".netrc" files, run the following command: 

$ sudo find /root /home -xdev -name .netrc

If any .netrc files exist, this is a finding.'
  desc 'fix', %q(The ".netrc" files contain logon information used to auto-logon into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any ".netrc" files should be removed.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19559r377249_chk'
  tag severity: 'medium'
  tag gid: 'V-218078'
  tag rid: 'SV-218078r603264_rule'
  tag stig_id: 'RHEL-06-000347'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-19557r377250_fix'
  tag 'documentable'
  tag legacy: ['SV-50420', 'V-38619']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
