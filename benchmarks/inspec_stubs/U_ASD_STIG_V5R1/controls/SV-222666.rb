control 'SV-222666' do
  title 'Production database exports must have database administration credentials and sensitive data removed before releasing the export.'
  desc 'Production database exports are often used to populate development databases. Test and development environments do not typically have the same rigid security protections that production environments do. When production data is used in test and development, the production database exports will need to be scrubbed to prevent information like passwords and other sensitive data from becoming available to development and test staff that may not have a need to know. Sensitive data should not be included in database exports because of classification, privacy, and other types of data protection requirement issues. Not all application developers have need-to-know sensitive information such as HIPAA data, Privacy Act Data, production admin passwords or classified data.'
  desc 'check', 'Review the application documentation and identify the existence of databases within the application architecture.

Ask the application admin to identify when data exports from this database are imported to test or development databases.
 
If no data is exported to test or development databases, this check is not applicable.

If there are such data exports, ask if the production database includes sensitive data identified by the data owner as sensitive such as passwords, financial, personnel, personal, HIPAA, Privacy Act, or classified data is included.

If any database exports include sensitive data and that data is not sanitized or removed prior to or immediately after import to the development database, this is a finding.'
  desc 'fix', 'Remove sensitive data from production database exports.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24336r493906_chk'
  tag severity: 'medium'
  tag gid: 'V-222666'
  tag rid: 'SV-222666r508029_rule'
  tag stig_id: 'APSC-DV-003310'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24325r493907_fix'
  tag 'documentable'
  tag legacy: ['V-70411', 'SV-85033']
  tag cci: ['CCI-002478', 'CCI-000366']
  tag nist: ['SC-28 (2)', 'CM-6 b']
end
