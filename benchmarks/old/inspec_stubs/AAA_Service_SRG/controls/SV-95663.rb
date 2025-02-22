control 'SV-95663' do
  title 'AAA Services must be configured to encrypt locally stored credentials using a FIPS-validated cryptographic module.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

AAA Services must enforce cryptographic representations of passwords when storing passwords in databases, configuration files, and log files. Passwords must be protected at all times; using a strong one-way hashing encryption algorithm with a salt is the standard method for providing a means to validate a password without having to store the actual password.

Performance and time required to access are factors that must be considered, and the one-way hash is the most feasible means of securing the password and providing an acceptable measure of password security. If passwords are stored in clear text, they can be plainly read and easily compromised.'
  desc 'check', "Where passwords are used, verify AAA Services are configured to encrypt locally stored credentials using a FIPS-validated cryptographic module. AAA Services may leverage the capability of an operating system or purpose-built module for this purpose. 

Confirm that databases, configuration files, and log files have encrypted representations for all passwords, and that no password strings are readable/discernable. Potential locations include the local file system where configurations and events are stored, or in a related database table.

Review AAA Services configuration for use of the MD5 algorithm to create password hashes.

If AAA Services are not configured to encrypt locally stored credentials using a FIPS-validated cryptographic module, this is a finding.

If AAA Services are configured to use MD5 to create password hashes, this is a finding.

Note: FIPS-validated cryptographic modules are listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  desc 'fix', 'Configure AAA Services to encrypt locally stored credentials using a FIPS-validated cryptographic module.

Configure all associated databases, configuration files, and audit files to use only encrypted representations for all passwords and so that no password strings are readable/discernable.'
  impact 0.7
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80691r2_chk'
  tag severity: 'high'
  tag gid: 'V-80953'
  tag rid: 'SV-95663r1_rule'
  tag stig_id: 'SRG-APP-000171-AAA-000510'
  tag gtitle: 'SRG-APP-000171-AAA-000510'
  tag fix_id: 'F-87809r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
