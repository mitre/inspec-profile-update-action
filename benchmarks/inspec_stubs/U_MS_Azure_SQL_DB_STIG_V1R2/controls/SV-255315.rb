control 'SV-255315' do
  title 'Azure SQL Database must associate organization-defined types of security labels having organization-defined security label values with information in transmission.'
  desc 'Without the association of security labels to information, there is no basis for Azure SQL Database to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy.

One example includes marking data as classified or CUI. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained. If the security labels are lost, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of Azure SQL Database, a third-party product, or custom application code.'
  desc 'check', 'If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, but a third-party solution, SQL Information Protection, or an Azure SQL Database Row-Level security solution is implemented that reliably maintains labels on information in transmission, this is a finding.'
  desc 'fix', 'Deploy SQL Information Protection (see link below) or Azure SQL Database Row-Level Security (see link below), a third-party software, or add custom data structures, data elements and application code to provide reliable security labeling of information in transmission.

https://docs.microsoft.com/en-us/azure/security-center/security-center-info-protection-policy?
https://msdn.microsoft.com/en-us/library/dn765131.aspx'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58988r877285_chk'
  tag severity: 'medium'
  tag gid: 'V-255315'
  tag rid: 'SV-255315r879691_rule'
  tag stig_id: 'ASQL-00-002700'
  tag gtitle: 'SRG-APP-000314-DB-000310'
  tag fix_id: 'F-58932r871070_fix'
  tag 'documentable'
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
