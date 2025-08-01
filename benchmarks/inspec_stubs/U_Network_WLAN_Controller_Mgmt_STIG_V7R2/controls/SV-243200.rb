control 'SV-243200' do
  title 'The network device must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Review the network device configuration to determine if an authentication server is defined for gaining administrative access. If so, there must be only one account of last resort configured locally for an emergency.

Verify the username and password for the local account of last resort is contained in a sealed envelope kept in a safe.

If an authentication server is used and more than one local account exists, this is a finding.'
  desc 'fix', 'Configure the device to allow only one local account of last resort for emergency access and store the credentials in a secure manner.'
  impact 0.5
  ref 'DPMS Target Network WLAN Controller Mgmt'
  tag check_id: 'C-46475r720053_chk'
  tag severity: 'medium'
  tag gid: 'V-243200'
  tag rid: 'SV-243200r879589_rule'
  tag stig_id: 'WLAN-ND-001300'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-46432r720054_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
