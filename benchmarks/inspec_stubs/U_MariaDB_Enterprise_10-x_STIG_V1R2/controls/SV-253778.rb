control 'SV-253778' do
  title 'MariaDB products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.

Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the version and release information.

Verify the MariaDB Enterprise Server version via one of the following methods: 

MariaDB> SELECT VERSION();

# mariadb --version

Verify the version is supported per the MariaDB support policy: 
https://mariadb.com/engineering-policies/ 

If the installed version of MariaDB is not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade MariaDB Enterprise to a supported version of the product.'
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57230r841857_chk'
  tag severity: 'high'
  tag gid: 'V-253778'
  tag rid: 'SV-253778r841859_rule'
  tag stig_id: 'MADB-10-012600'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-57181r841858_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
