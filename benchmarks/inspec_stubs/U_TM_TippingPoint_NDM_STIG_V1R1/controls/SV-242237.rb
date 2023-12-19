control 'SV-242237' do
  title 'The TippingPoint SMS must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort because it is intended to be used as a last resort, and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'In the SMS client, ensure the SMS has only a single local account. 

Select Admin >> Authentication and Authorization >> Users.

If more than one user is enabled under user accounts, this is a finding.'
  desc 'fix', 'In the SMS client, ensure the SMS has only a single local emergency account.

1. Select Admin >> Authentication and Authorization >> Users.
2. Delete all but the user account being used for local emergency user account/account of last resort functions.

The local emergency user account must not be disabled after 35 days of inactivity. Log in to the serial console and set the following command:

set pwd.emergency-user=<USERNAME>'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45512r710716_chk'
  tag severity: 'medium'
  tag gid: 'V-242237'
  tag rid: 'SV-242237r710718_rule'
  tag stig_id: 'TIPP-NM-000210'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-45470r710717_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
