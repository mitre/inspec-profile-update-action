control 'SV-202051' do
  title 'The network device must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Review the network device configuration to determine if an account of last resort is configured. Verify default admin and other vendor-provided accounts are disabled, removed, or renamed where possible. Verify the username and password for the account of last resort is contained within a sealed envelope and kept in a safe. 

If one local account does not exist for use as the account of last resort, this is a finding.'
  desc 'fix', 'Configure the device to only allow one local account for use as the account of last resort.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2177r381755_chk'
  tag severity: 'medium'
  tag gid: 'V-202051'
  tag rid: 'SV-202051r879589_rule'
  tag stig_id: 'SRG-APP-000148-NDM-000346'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-2178r381756_fix'
  tag 'documentable'
  tag legacy: ['SV-78491', 'V-64001']
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
