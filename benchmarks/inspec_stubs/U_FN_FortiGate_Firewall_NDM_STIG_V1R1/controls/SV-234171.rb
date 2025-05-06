control 'SV-234171' do
  title 'The FortiGate device must log all user activity.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege:
To verify that logging is enabled:
1. Click Log and Report.
2. Click Log Settings.
3. Scroll down to Log Settings and ensure that Event Logging is set to "All" or "Customize" with System activity events checked.

If Event Logging is not set to ALL or Customize with System activity event checked, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.
1. Click Log and Report.
2. Click Log Settings.
3. Scroll to Log Settings.
4. For Event Logging, select ALL or Customize.
5. If Customize is selected, ensure to configure, at least, System activity event.
6. Click Apply.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37356r611700_chk'
  tag severity: 'medium'
  tag gid: 'V-234171'
  tag rid: 'SV-234171r628777_rule'
  tag stig_id: 'FGFW-ND-000060'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-37321r611701_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
