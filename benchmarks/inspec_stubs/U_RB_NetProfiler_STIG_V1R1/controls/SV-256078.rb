control 'SV-256078' do
  title 'The Riverbed NetProfiler must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged-level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort because it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Navigate to the Configuration >> Account Management >> User Accounts page.

If accounts exist other than the "admin" account, this is a finding.'
  desc 'fix', %q(Use of the factory-created "admin" account as the account of last resort is strongly recommended. It must have a DOD-compliant password and be securely stored in a safe for emergency but not day-to-day use.

Go to the Configuration >> Manage Accounts >> User Accounts >> Settings page.

In the Global account settings configuration window, ensure the "Prevent user 'admin' from being locked out via a DOS attack" feature applies to only the factory-created admin account.)
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59752r882740_chk'
  tag severity: 'medium'
  tag gid: 'V-256078'
  tag rid: 'SV-256078r882742_rule'
  tag stig_id: 'RINP-DM-000027'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-59695r882741_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
