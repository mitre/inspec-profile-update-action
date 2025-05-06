control 'SV-217898' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).'
  desc 'Using a stronger hashing algorithm makes password cracking attacks more difficult.'
  desc 'check', %q(Inspect the "password" section of "/etc/pam.d/system-auth", "/etc/pam.d/system-auth-ac", "/etc/pam.d/password-auth", "/etc/pam.d/password-auth-ac" and other files in "/etc/pam.d" to identify the number of occurrences where the “pam_unix.so” module is used in the “password” section.

$ grep -E -c 'password.*pam_unix.so' /etc/pam.d/*

/etc/pam.d/atd:0
/etc/pam.d/config-util:0
/etc/pam.d/crond:0
/etc/pam.d/login:0
/etc/pam.d/other:0
/etc/pam.d/passwd:0
/etc/pam.d/password-auth:1
/etc/pam.d/password-auth-ac:1
/etc/pam.d/sshd:0
/etc/pam.d/su:0
/etc/pam.d/sudo:0
/etc/pam.d/system-auth:1
/etc/pam.d/system-auth-ac:1
/etc/pam.d/vlock:0

Note: The number adjacent to the file name indicates how many occurrences of the “pam_unix.so” module are found in the password section.

If the “pam_unix.so” module is not defined in the “password” section of “/etc/pam.d/system-auth”, “/etc/pam.d/system-auth-ac”, “/etc/pam.d/password-auth”, and “/etc/pam.d/password-auth-ac” at a minimum, this is a finding.

Verify that the “sha512” variable is used with each instance of the “pam_unix.so” module in the “password” section:

$ grep password /etc/pam.d/* | grep pam_unix.so | grep sha512

/etc/pam.d/password-auth:password     sufficient    pam_unix.so sha512 [other arguments…]
/etc/pam.d/password-auth-ac:password    sufficient    pam_unix.so sha512 [other arguments…]
/etc/pam.d/system-auth:password     sufficient    pam_unix.so sha512 [other arguments…]
/etc/pam.d/system-auth-ac:password     sufficient    pam_unix.so sha512 [other arguments…]

If this list of files does not coincide with the previous command, this is a finding. 

If any of the identified “pam_unix.so” modules do not use the “sha512” variable, this is a finding.)
  desc 'fix', 'In "/etc/pam.d/system-auth”, "/etc/pam.d/system-auth-ac", “/etc/pam.d/password-auth”, and “/etc/pam.d/password-auth-ac”, among potentially other files, the "password" section of the files controls which PAM modules execute during a password change. Set the "pam_unix.so" module in the "password" section to include the argument "sha512", as shown below: 

password sufficient pam_unix.so sha512 [other arguments...]

This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.

Note: Any updates made to "/etc/pam.d/system-auth" will be overwritten by the "authconfig" program. The "authconfig" program should not be used.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19379r462388_chk'
  tag severity: 'medium'
  tag gid: 'V-217898'
  tag rid: 'SV-217898r603264_rule'
  tag stig_id: 'RHEL-06-000062'
  tag gtitle: 'SRG-OS-000120'
  tag fix_id: 'F-19377r462389_fix'
  tag 'documentable'
  tag legacy: ['V-38574', 'SV-50375']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
