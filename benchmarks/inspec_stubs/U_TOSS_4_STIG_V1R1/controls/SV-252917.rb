control 'SV-252917' do
  title 'The TOSS pam_unix.so module must be configured in the password-auth file to use a FIPS 140-2-approved cryptographic hashing algorithm for system authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

TOSS systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify that the pam_unix.so module is configured to use sha512.

Check that the pam_unix.so module is configured to use sha512 in /etc/pam.d/password-auth with the following command:

$ sudo grep password /etc/pam.d/password-auth | grep pam_unix

password sufficient pam_unix.so sha512

If "sha512" is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to use a FIPS 140-2-approved cryptographic hashing algorithm for system authentication.

Edit and/or modify the following line in the "/etc/pam.d/password-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56370r824073_chk'
  tag severity: 'medium'
  tag gid: 'V-252917'
  tag rid: 'SV-252917r824075_rule'
  tag stig_id: 'TOSS-04-010060'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-56320r824074_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
