control 'SV-217125' do
  title 'The SUSE operating system must not be configured to allow blank or null passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the SUSE operating is not configured to allow blank or null passwords.

Check that blank or null passwords cannot be used by running the following command:

# grep pam_unix.so /etc/pam.d/* | grep nullok
If this produces any output, it may be possible to log on with accounts with empty passwords.

If null passwords can be used, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to not allow blank or null passwords.

Remove any instances of the "nullok" option in "/etc/pam.d/common-auth" and "/etc/pam.d/common-password" to prevent logons with empty passwords.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18353r369531_chk'
  tag severity: 'medium'
  tag gid: 'V-217125'
  tag rid: 'SV-217125r603262_rule'
  tag stig_id: 'SLES-12-010231'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18351r369532_fix'
  tag 'documentable'
  tag legacy: ['V-81785', 'SV-96499']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
