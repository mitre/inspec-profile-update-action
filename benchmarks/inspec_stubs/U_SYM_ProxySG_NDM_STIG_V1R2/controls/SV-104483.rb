control 'SV-104483' do
  title 'Symantec ProxySG must be configured with only one local account that is used as the account of last resort.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Verify local accounts besides the account of last resort do not exist.

Show security local-user-list
View "Users:" list

If any users show in the "Users" configuration list other than the default admin user, this is a finding.'
  desc 'fix', 'Remove local accounts that are not the account of last resort.

1. Log on to the Web Management Console.
2. Click "Local".
3. If a local realm exists on the list, delete the realm.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94653'
  tag rid: 'SV-104483r1_rule'
  tag stig_id: 'SYMP-NM-000010'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-100771r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
