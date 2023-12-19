control 'SV-100115' do
  title 'The SLES for vRealize must automatically remove or disable temporary user accounts after 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'For every existing temporary account, run the following command to obtain its account expiration information:

# chage -l system_account_name

Verify each of these accounts has an expiration date set within "72" hours.

If any temporary accounts have no expiration date set or do not expire within "72" hours, this is a finding.'
  desc 'fix', 'In the event temporary accounts are required, configure the system to terminate them after a 72-hour time period. For every temporary account, run the following command to set an expiration date on it, substituting "system_account_name" to the appropriate value:

# chage -E `date -d "+3 days" +%Y-%m-%d` system_account_name

`date -d "+3 days" +%Y-%m-%d` gets the "72" expiration date for the account at the time of running the command.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89157r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89465'
  tag rid: 'SV-100115r1_rule'
  tag stig_id: 'VRAU-SL-000010'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-96207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
