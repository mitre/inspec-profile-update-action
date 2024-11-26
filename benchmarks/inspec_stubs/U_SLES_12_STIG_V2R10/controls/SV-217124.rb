control 'SV-217124' do
  title 'The SUSE operating system must configure the Linux Pluggable Authentication Modules (PAM) to only store encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'Verify the SUSE operating system configures the Linux PAM to only store encrypted representations of passwords. All account passwords must be hashed with SHA512 encryption strength.

Check that PAM is configured to create SHA512 hashed passwords by running the following command:

# grep pam_unix.so /etc/pam.d/common-password
password required pam_unix.so sha512

If the command does not return anything or the returned line is commented out, has a second column value different from "required", or does not contain "sha512", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system Linux PAM to only store encrypted representations of passwords. All account passwords must be hashed with SHA512 encryption strength.

Edit "/etc/pam.d/common-password" and edit the line containing "pam_unix.so" to contain the SHA512 keyword after third column. Remove the "nullok" option.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18352r369528_chk'
  tag severity: 'medium'
  tag gid: 'V-217124'
  tag rid: 'SV-217124r877397_rule'
  tag stig_id: 'SLES-12-010230'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-18350r369529_fix'
  tag satisfies: ['SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag legacy: ['V-77105', 'SV-91801']
  tag cci: ['CCI-000196', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-7']
end
