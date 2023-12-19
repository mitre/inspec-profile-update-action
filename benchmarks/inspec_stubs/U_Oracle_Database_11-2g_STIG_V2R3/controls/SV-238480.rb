control 'SV-238480' do
  title 'Use of the DBMS software installation account must be restricted.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account. 

To limit exposure when operating from within a privileged account or role, the application must support organizational requirements that users of information system accounts, or roles, with access to organization-defined lists of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

Use of privileged accounts for non-administrative purposes puts data at risk of unintended or unauthorized loss, modification, or exposure. In particular, DBA accounts if used for non-administration application development or application maintenance can lead to miss-assignment of privileges where privileges are inherited by object owners. It may also lead to loss or compromise of application data where the elevated privileges bypass controls designed in and provided by applications.

The DBMS software installation account may require privileges not required for database administration or other functions. Use of accounts configured with excess privileges may result in the loss or compromise of data or system settings due to elevated privileges that bypass controls designed to protect them.'
  desc 'check', 'Review system documentation to identify the installation account.

Verify whether the account is used for anything involving interactive activity beyond DBMS software installation, upgrade, and maintenance actions.

If the account is used for anything involving interactive activity beyond DBMS software installation, upgrade, and maintenance actions, this is a finding.'
  desc 'fix', 'Restrict interactive use of the DBMS software installation account to DBMS software installation, upgrade, and maintenance actions only.

If possible, disable the installation accounts when authorized actions are not being performed. Otherwise, disable the use of the account(s) for interactive activity.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41691r667612_chk'
  tag severity: 'medium'
  tag gid: 'V-238480'
  tag rid: 'SV-238480r667614_rule'
  tag stig_id: 'O112-OS-004600'
  tag gtitle: 'SRG-APP-000133-DB-000198'
  tag fix_id: 'F-41650r667613_fix'
  tag 'documentable'
  tag legacy: ['V-52425', 'SV-66641']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
