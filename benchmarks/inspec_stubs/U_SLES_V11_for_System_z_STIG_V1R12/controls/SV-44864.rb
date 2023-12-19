control 'SV-44864' do
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors.  The use of unapproved algorithms may result in weak password hashes more vulnerable to compromise.'
  desc 'check', "Check the /etc/default/passwd file for the CRYPT_FILES variable setting.  
Procedure:
# grep -v '^#' /etc/default/passwd | grep -i crypt_files

CRYPT_FILES must be set to SHA256 or SHA512.  If it is not set, or it is set to some other value this is a finding."
  desc 'fix', 'Edit the /etc/default/passwd file and add or change the CRYPT_FILES variable setting so that it contains:
   CRYPT_FILES=sha256
             OR 
   CRYPT_FILES=sha512

In SLES 11 SP2 this option can also be configured with the YaST ‘Security and Users’ module.  Run the ‘Security Center and Hardening’ application, then select ‘Password Settings’.  Use the ‘Password Encryption Method’ drop-down to select either ‘SHA-256’ or ‘SHA-512’.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42326r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22303'
  tag rid: 'SV-44864r1_rule'
  tag stig_id: 'GEN000590'
  tag gtitle: 'GEN000590'
  tag fix_id: 'F-38297r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
