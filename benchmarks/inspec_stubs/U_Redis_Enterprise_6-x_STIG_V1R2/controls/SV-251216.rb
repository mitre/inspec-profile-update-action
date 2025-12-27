control 'SV-251216' do
  title 'Redis Enterprise products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities. Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the system documentation and interview the database administrator. Identify all database software components.

Review the version and release information.
1. Log in to the adminUI console as an authorized user.
2. Navigate to the cluster tab and select configuration.
3. Check the version number next to Redis Labs Enterprise Cluster.

Access the below Redis website or use other means to verify the version is still supported:
https://docs.redislabs.com/latest/rs/administering/product-lifecycle

If the DBMS or any of the software components are not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54651r804836_chk'
  tag severity: 'medium'
  tag gid: 'V-251216'
  tag rid: 'SV-251216r855612_rule'
  tag stig_id: 'RD6X-00-007950'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-54605r804837_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
