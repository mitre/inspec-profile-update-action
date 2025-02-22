control 'SV-242614' do
  title 'The Cisco ISE must be configured with only one local web-based account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions.

Accounts necessary for authorized system functions are permitted, but must be secured to prevent use for local login and remote exploitation. These accounts should either be disabled for login for non-system functions and/or use a compliant authenticator (Example RSA SecureID token)."
  desc 'check', 'View the local admin users.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Users >>View.
2. Verify there are only two local accounts are defined. Both must be in the Super User group. These users must be the web-based Account of Last Resort and the default CLI admin user.

If the Cisco ISE has unauthorized local users defined, this is a finding.'
  desc 'fix', 'Create a local web-based administrator. ONLY one web-based admin account should exist on the local device. The default CLI account is also local and cannot be removed.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Users >> Add.
2. From the drop-down, choose Create an Admin User.
3. Enter the admin name and other information. 
4. Add the Super User group.
5. Click "Submit".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45889r714150_chk'
  tag severity: 'medium'
  tag gid: 'V-242614'
  tag rid: 'SV-242614r822757_rule'
  tag stig_id: 'CSCO-NM-000080'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-45846r714151_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
