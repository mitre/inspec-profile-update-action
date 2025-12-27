control 'SV-258607' do
  title 'The ICS must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.

Click the tab "Users" and verify that more than one user does not exist.

If the ICS is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Click the tab "Users".
2. Create the emergency local user, or click the default admin user.
3. Click the box for "Enabled".
4. Click the box for "Allow Console Access".
5. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62347r930507_chk'
  tag severity: 'medium'
  tag gid: 'V-258607'
  tag rid: 'SV-258607r930509_rule'
  tag stig_id: 'IVCS-NM-000271'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-62256r930508_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
