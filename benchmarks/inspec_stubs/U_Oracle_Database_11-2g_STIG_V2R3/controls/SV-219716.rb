control 'SV-219716' do
  title 'Sensitive information from production database exports must be modified before being imported into a development database.'
  desc 'Data export from production databases may include sensitive data. Application developers do not have a need to know to sensitive data. Any access they may have to production data would be considered unauthorized access and subject the sensitive data to unlawful or unauthorized disclosure. See DODD 8500.1 for a definition of Sensitive Information.'
  desc 'check', 'If the database being reviewed is a production database, this check is Not a Finding.

Review policy, procedures and restrictions for data imports of production data containing sensitive information into development databases.

If data imports of production data are allowed, review procedures for protecting any sensitive data included in production exports.

If sensitive data is included in the exports and no procedures are in place to remove or modify the data to render it not sensitive prior to import into a development database or policy and procedures are not in place to ensure authorization of development personnel to access sensitive information contained in production data, this is a Finding.'
  desc 'fix', 'Develop, document and implement policy, procedures and restrictions for production data import.

Require any users assigned privileges that allow the export of production data from the database to acknowledge understanding of import policies, procedures and restrictions.

Restrict permissions of development personnel requiring use or access to production data imported into development databases containing sensitive information to authorized users.

Implement policy and procedures to modify or remove sensitive information in production exports prior to import into development databases.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21441r306997_chk'
  tag severity: 'medium'
  tag gid: 'V-219716'
  tag rid: 'SV-219716r401224_rule'
  tag stig_id: 'O112-BP-023300'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21440r306998_fix'
  tag 'documentable'
  tag legacy: ['SV-68243', 'V-54003']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
