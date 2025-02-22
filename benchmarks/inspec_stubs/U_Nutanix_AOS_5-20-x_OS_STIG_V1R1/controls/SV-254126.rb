control 'SV-254126' do
  title 'Nutanix AOS must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.

'
  desc 'check', 'Nutanix AOS does not natively support temporary user accounts, named or otherwise. However, if temporary accounts are created, they must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

Verify that temporary accounts have been provisioned with an expiration date of 72 hours.

For every existing temporary account, run the following command to obtain its account expiration information.

$ sudo chage -l system_account_name

Verify each of these accounts has an expiration date set within 72 hours.

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure any temporary account(s) that have been created with an expiration date exceeding the DoD-defined time period of 72 hours by running the following command:

sudo chage -E `date -d "+3 days" +%Y-%m-%d` system_account_name'
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57611r846464_chk'
  tag severity: 'low'
  tag gid: 'V-254126'
  tag rid: 'SV-254126r846466_rule'
  tag stig_id: 'NUTX-OS-000100'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-57562r846465_fix'
  tag satisfies: ['SRG-OS-000002-GPOS-00002', 'SRG-OS-000123-GPOS-00064']
  tag 'documentable'
  tag cci: ['CCI-000016', 'CCI-001682']
  tag nist: ['AC-2 (2)', 'AC-2 (2)']
end
