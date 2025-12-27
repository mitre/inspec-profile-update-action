control 'SV-77725' do
  title 'The password hashes stored on the system must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors. The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', 'To verify the password hash setting, run the following command: 

# grep -i "^password" /etc/pam.d/passwd | grep sufficient

If sha512 is not listed, this is a finding.'
  desc 'fix', 'To set the remember option, add or correct the following line in "/etc/pam.d/passwd":

password   sufficient   /lib/security/$ISA/pam_unix.so use_authtok nullok shadow sha512 remember=5'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63969r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63235'
  tag rid: 'SV-77725r1_rule'
  tag stig_id: 'ESXI-06-000033'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69153r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
