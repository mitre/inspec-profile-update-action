control 'SV-90623' do
  title 'CounterACT must send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Possible audit processing failures also include the inability of ALG to write to the central audit log.

While this requirement also applies to the event monitoring system (e.g., Syslog, Security Information and Event Management [SIEM], or SNMP servers), CounterACT can also be configured to send notifications.'
  desc 'check', 'Verify CounterACT sends an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.

1. Log in to the CounterACT Administrator interface.
2. Select Tools >> Options.
3. Select General.
4. Select the "+" next to general to open the submenu. Select email Preferences.
5. Ensure that the ISSO/SCA email address is configuration for notifications. 

If CounterACT does not send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs, this is a finding.'
  desc 'fix', 'Configure CounterACT to send all alert notifications to, at a minimum, the ISSO and SCA when an audit processing failure occurs.

1. Log in to CounterACT’s Administrator interface.
2. Select Tools >> Options.
3. Select General.
4. Select the "+" next to general to open the submenu. Select email Preferences.
5. Ensure that the ISSO/SCA email address is configuration for notifications.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75935'
  tag rid: 'SV-90623r1_rule'
  tag stig_id: 'CACT-AG-000004'
  tag gtitle: 'SRG-NET-000088-ALG-000054'
  tag fix_id: 'F-82573r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
