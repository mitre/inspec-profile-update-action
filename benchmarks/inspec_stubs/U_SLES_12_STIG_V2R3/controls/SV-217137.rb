control 'SV-217137' do
  title 'The SUSE operating system must provision temporary accounts with an expiration date for 72 hours.'
  desc 'If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be used to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts must be set upon account creation.

Temporary accounts are established as part of normal account activation procedures when there is a need for short-term accounts without the demand for immediacy in account activation.

If temporary accounts are used, the SUSE operating system must be configured to automatically terminate these types of accounts after a DoD-defined time period of 72 hours.

To address access requirements, many SUSE operating systems may be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify that the SUSE operating system provisions temporary accounts with an expiration date for "72" hours.

Ask the System Administrator if any temporary accounts have been added to the system. For every existing temporary account, run the following command to obtain its account expiration information:

# sudo chage -l system_account_name

Verify each of these accounts has an expiration date that is within "72" hours of its creation.

If any temporary accounts have no expiration date set or do not expire within "72" hours of their creation, this is a finding.'
  desc 'fix', 'In the event temporary accounts are required, configure the SUSE operating system to terminate them after "72" hours. 

For every temporary account, run the following command to set an expiration date on it, substituting "system_account_name" with the appropriate value:

# sudo chage -E `date -d "+3 days" +%Y-%m-%d` system_account_name

`date -d "+3 days" +%Y-%m-%d` sets the 72-hour expiration date for the account at the time the command is run.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18365r369567_chk'
  tag severity: 'medium'
  tag gid: 'V-217137'
  tag rid: 'SV-217137r603262_rule'
  tag stig_id: 'SLES-12-010360'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-18363r369568_fix'
  tag 'documentable'
  tag legacy: ['V-77129', 'SV-91825']
  tag cci: ['CCI-000016']
  tag nist: ['AC-2 (2)']
end
