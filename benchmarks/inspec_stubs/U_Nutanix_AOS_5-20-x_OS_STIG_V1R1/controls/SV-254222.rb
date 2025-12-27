control 'SV-254222' do
  title 'Nutanix AOS pam_unix.so module must be configured in the password-auth file to use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not verified and therefore, cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Verify that the pam_unix.so module is configured to use SHA512.

$ sudo grep password /etc/pam.d/password-auth | grep pam_unix
password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok

$ sudo grep password /etc/pam.d/system-auth | grep pam_unix
password    sufficient    pam_unix.so sha512 shadow try_first_pass use_authtok

If "sha512" is not an option in both outputs, or is commented out, this is a finding.'
  desc 'fix', 'Configure the pam.d modules to comply with FIPS 140-2:

1. Enable high-strength passwords:
$ ncli cluster edit-cvm-security-params enable-high-strength-password=true

2. After enabling the high-strength passwords, the system will process the salt stack to enable the DoD versions of the pam.d files. Recheck the Check Text for compliance.  

To run the salt command manually to enable the pam.d auth files, run the following command (high-strength passwords must be set to true):
$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57707r846752_chk'
  tag severity: 'high'
  tag gid: 'V-254222'
  tag rid: 'SV-254222r846754_rule'
  tag stig_id: 'NUTX-OS-001380'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-57658r846753_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
