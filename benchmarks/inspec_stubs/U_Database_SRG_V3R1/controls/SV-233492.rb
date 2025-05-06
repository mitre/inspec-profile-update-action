control 'SV-233492' do
  title 'DBMS products must be a version supported by the vendor.'
  desc 'Unsupported commercial and database systems should not be used because fixes to newly identified bugs will not be implemented by the vendor. The lack of support can result in potential vulnerabilities.
Systems at unsupported servicing levels or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

When maintenance updates and patches are no longer available, the database software is no longer considered supported and should be upgraded or decommissioned.'
  desc 'check', 'Review the system documentation and interview the database administrator.

Identify all database software components.

Review the version and release information.

Access the vendor website or use other means to verify the version is still supported.

If the DBMS or any of the software components are not supported by the vendor, this is a finding.'
  desc 'fix', 'Remove or decommission all unsupported software products.

Upgrade unsupported DBMS or unsupported components to a supported version of the product.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-36687r604894_chk'
  tag severity: 'medium'
  tag gid: 'V-233492'
  tag rid: 'SV-233492r617447_rule'
  tag stig_id: 'SRG-APP-000456-DB-000400'
  tag gtitle: 'SRG-APP-000456-DB-000400'
  tag fix_id: 'F-36652r604895_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
