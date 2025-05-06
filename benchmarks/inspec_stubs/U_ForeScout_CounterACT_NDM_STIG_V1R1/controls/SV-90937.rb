control 'SV-90937' do
  title 'In the event the authentication server is unavailable, one local account must be created for use as the account of last resort.'
  desc "Authentication for administrative (privileged-level) access to the device is required at all times. An account can be created on CounterACT's local database for use in an emergency, such as when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since the emergency administration account is strictly intended to be used only as a last resort when immediate administrative access is absolutely necessary.

The number of local accounts is restricted to one.  The username and password for the emergency account is contained within a sealed envelope kept in a safe. All other users/groups should leverage the external directory. Remove any other accounts using Single-Local. The default admin account may be used to fulfill this requirement (requires DoD compliant password or cryptographically generated shared secret)."
  desc 'check', 'Verify that only one local account exists and it has full administrator privileges.

1. Log on to the CounterACT Administrator UI. 
2. From the menu, select Tools >> Options >> User Console and Options.

If more than one local user account exists, this is a finding.'
  desc 'fix', 'Create a local account with full administrator privileges to be used as the account of last resort.  The default admin account may be used to fulfill this requirement.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options.

Remove unneeded accounts, if any.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76249'
  tag rid: 'SV-90937r1_rule'
  tag stig_id: 'CACT-NM-000027'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-82885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
