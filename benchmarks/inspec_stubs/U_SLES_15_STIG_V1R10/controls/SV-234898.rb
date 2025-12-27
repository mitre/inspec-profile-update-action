control 'SV-234898' do
  title 'The SUSE operating system must not be configured to allow blank or null passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the SUSE operating system is not configured to allow blank or null passwords.

Check that blank or null passwords cannot be used by running the following command:

> grep pam_unix.so /etc/pam.d/* | grep nullok

If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to not allow blank or null passwords.

Remove any instances of the "nullok" option in "/etc/pam.d/common-auth" and "/etc/pam.d/common-password" to prevent logons with empty passwords.'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38086r618963_chk'
  tag severity: 'high'
  tag gid: 'V-234898'
  tag rid: 'SV-234898r622137_rule'
  tag stig_id: 'SLES-15-020300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38049r618964_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
