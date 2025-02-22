control 'SV-53413' do
  title 'Use of the SQL Server software installation account must be restricted to SQL Server software installation.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account. SQL Server does support the organizational requirement that users of information system accounts with access to an organization-defined list of security functions or security-relevant information use non-privileged accounts and roles, when accessing other (non-security) system functions.

Use of privileged accounts for non-administrative purposes puts data at risk of unintended or unauthorized loss, modification, or exposure. In particular, DBA accounts if used for non-administration application development or application maintenance can lead to miss-assignment of privileges where privileges are inherited by object owners. It may also lead to loss or compromise of application data where the elevated privileges bypass controls designed in, and provided by, applications.

The SQL Server installation account requires privileges not required for SQL Server administration or other functions. Use of accounts configured with excess privileges may result in the loss or compromise of data or system settings due to elevated privileges that bypass controls designed to protect them.'
  desc 'check', 'Review system documentation to identify the installation account. Verify whether the account is used for anything beyond SQL Server software installation, upgrade, and maintenance actions.

If the account is used for anything beyond SQL Server installation, upgrade, and maintenance actions, this is a finding.'
  desc 'fix', 'Restrict usage of the SQL Server installation account to SQL Server installation, upgrade, and maintenance actions only.

Disable installation accounts when authorized actions are not being performed.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47655r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41038'
  tag rid: 'SV-53413r2_rule'
  tag stig_id: 'SQL2-00-010100'
  tag gtitle: 'SRG-APP-000063-DB-000022'
  tag fix_id: 'F-46337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
