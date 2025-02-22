control 'SV-230932' do
  title 'Forescout must be configured with only one web account and one CLI account of last resort with limited access and used only when the authentication server is unavailable.'
  desc %q(Authentication for administrative (privileged-level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the "account of last resort" since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit must be added to the envelope as a record. Administrators must secure the credentials and disable the root account (if possible) when not needed for system administration functions.)
  desc 'check', 'Verify only one local account exists and that it has full administrator privileges.

1. Log on to the Forescout Administrator UI. 
2. From the menu, select Tools >> Options >> CounterACT User Profiles.

If local accounts in the CounterACT User profile or CLI exist other than the accounts of last resort, this is a finding.'
  desc 'fix', 'There are two default accounts. The CLIAdmin root account can only be used with the CLI. To access the CLI, an account must be created that only has access to the CLI. Accounts created in CounterACT user profile in the web management tools do not have access to login to the CLI. The default console account "Admin" allows access to the web management tool. These accounts can be used as the accounts of last resort or two other accounts may be created for this purpose as long as a strong password that meets DoD requirements is used for both.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterACT user profiles.

Remove unauthorized local accounts not identified as the account of last resort.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33862r603635_chk'
  tag severity: 'medium'
  tag gid: 'V-230932'
  tag rid: 'SV-230932r615886_rule'
  tag stig_id: 'FORE-NM-000030'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-33835r603636_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
