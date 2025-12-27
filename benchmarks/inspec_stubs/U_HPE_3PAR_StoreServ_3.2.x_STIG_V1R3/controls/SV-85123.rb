control 'SV-85123' do
  title 'The storage system must be configured to have only 1 emergency account which can be accessed without LDAP, and which has full administrator capabilities.'
  desc 'While LDAP allows the storage system to support stronger authentication and provides additional auditing, it also places a dependency on an external entity in the operational environment. The existence of a single local account with a strong password means that administrators can continue to access the storage system in the event the LDAP system is temporarily unavailable.'
  desc 'check', 'Verify that only essential local accounts are configured. Enter the following command:

cli% showuser

If the output shows users other than the four accounts below, this is a finding:

3paradm
3parsvc
3parsnmpuser
3parcimuser'
  desc 'fix', 'Display users with the following command:

cli% showuser

If the accounts "3parbrowse", "3paredit", or "3parservice" exist, see HP3P-32-001504 for removal instructions specific to these accounts.

If the account "3parcimuser" exists see HP3P-32-001002 for removal instructions specific to that account.

Otherwise, remove all accounts except "3paradm", "3parsvc", "3parsnmpuser", and "3parcimuser" using the following command:

cli% removeuser <username>

Confirm the operation with "y".'
  impact 0.7
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70901r2_chk'
  tag severity: 'high'
  tag gid: 'V-70501'
  tag rid: 'SV-85123r2_rule'
  tag stig_id: 'HP3P-32-001501'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-76739r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
