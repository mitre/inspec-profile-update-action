control 'SV-255279' do
  title 'The HPE 3PAR OS must be configured to have only one emergency account that can be accessed without LDAP and that has full administrator privileges.'
  desc 'While LDAP allows the storage system to support stronger authentication, and provides additional auditing, it also places a dependency on an external entity in the operational environment. The existence of a single local account with a strong password means that administrators can continue to access the storage system in event the LDAP system is temporarily unavailable.

A non-LDAP enabled emergency administrator account is required in the event that LDAP fails. This account will allow the organization to successfully administer the system during an LDAP outage. Once LDAP services have been restored, the password for this account must be changed and stored in a DOD approved safe.

The product requires at least one local account to be present. However, the administrator must still manually remove all other local accounts, except for the emergency account, after the product has been configured for operation.

The 3paradm account is a user bootstrap account. During installation, the user must use it to create a new local super user account. Once that is done, the 3paradm account must be removed.

The 3parsvc account is used internally by the system.

The 3parsnmp account was created in the fix text for HP3P-33-001300.'
  desc 'check', 'Verify that only essential local accounts are configured.
cli% showuser

If the output shows users other than the three accounts below, this is a finding.
--3paradm (or some other customer chosen account with "super" role)
--3parsnmpuser
--3parsvc'
  desc 'fix', 'Display users
cli% showuser

Remove all accounts except:
--3paradm (or other customer-created "super" role account)
--3parsnmpuser
--3parsvc

Use the command:
cli% removeuser <username>
and confirm the operation with "y".'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58952r870154_chk'
  tag severity: 'medium'
  tag gid: 'V-255279'
  tag rid: 'SV-255279r870156_rule'
  tag stig_id: 'HP3P-33-001501'
  tag gtitle: 'SRG-OS-000123-GPOS-00064'
  tag fix_id: 'F-58896r870155_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
