control 'SV-52489' do
  title 'The system must use a FIPS 140-2-approved cryptographic hashing algorithm for generating account password hashes.'
  desc 'Systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2-approved successors. The use of unapproved algorithms may result in weak password hashes that are more vulnerable to compromise.'
  desc 'check', 'For Trusted Mode:
MD5 is currently the only available hashing function. Per vendor documentation, this algorithm will not be updated, due to TS being deprecated/replaced by SMSE.

For SMSE:
Check the system password for use of cryptographic hashes using the SHA-2 family of algorithms or FIPS 140-2-approved successors.

# egrep “CRYPT_ALGORITHMS_DEPRECATE|CRYPT_DEFAULT” /etc/default/security

The following is an example output from the above command:
CRYPT_ALGORITHMS_DEPRECATE=__unix__
CRYPT_DEFAULT=6

If the attributes “CRYPT_ALGORITHMS_DEPRECATE” and “CRYPT_DEFAULT” are not set per the above example output, this is a finding.'
  desc 'fix', 'For Trusted Mode:
Note: There is no fix for Trusted Mode/Systems (TS). MD5 is currently used, and per vendor documentation, this algorithm will not be updated due to TS being deprecated/replaced by SMSE.

For SMSE:
Note: There may be additional package/bundle updates that must be installed to support attributes in the /etc/default/security file.

Use the SAM/SMH interface (/etc/default/security file) to update the attribute. See the below example:
CRYPT_ALGORITHMS_DEPRECATE=__unix__
CRYPT_DEFAULT=6

If manually editing the /etc/default/security file, save any change(s) before exiting the editor.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-47035r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22303'
  tag rid: 'SV-52489r3_rule'
  tag stig_id: 'GEN000590'
  tag gtitle: 'GEN000590'
  tag fix_id: 'F-45448r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
