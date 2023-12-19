control 'SV-234824' do
  title 'The SUSE operating system must employ FIPS 140-2 approved cryptographic hashing algorithm for system authentication (system-auth).'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

SUSE operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify the SUSE operating system requires that "pam_unix.so auth" is configured to use SHA512

Check the algorithms used to hash system passwords with the command:

> grep pam_unix.so /etc/pam.d/common-auth
auth required pam_unix.so sha512 try_first_pass

If the command does not return anything, the returned line is commented out, or has a second column value different from "required", or does not contain "sha512", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to require "pam_unix.so auth" to use SHA512.

Edit "/etc/pam.d/common-auth" and edit the line containing "pam_unix.so" to contain the option "sha512" after the third column.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38012r618741_chk'
  tag severity: 'medium'
  tag gid: 'V-234824'
  tag rid: 'SV-234824r622137_rule'
  tag stig_id: 'SLES-15-010250'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-37975r618742_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
