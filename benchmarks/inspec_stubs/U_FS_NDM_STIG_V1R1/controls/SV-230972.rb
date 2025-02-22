control 'SV-230972' do
  title 'Forescout must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the Information System Security Officer (ISSO).'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can be used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Check the Forescout logs periodically to ensure proper auditing functions are still enabled and have not been changed. A proper security policy performs periodic checks to help ensure the proper information is being gathered in the event of a security breach, or internal/external threat. 

If the Forescout auditing functions are disabled or have been changed, this is a finding.'
  desc 'fix', 'Establish and document a procedure that periodically checks to ensure audit logs are in keeping with the security best practices of detailed security audit logs.

1. Log on to the Forescout UI.
2. Select Tools >> Options >> Modules >> Syslog >> Add.
3. Configure the:
     Server Address
     Server Port 
     Select Use TLS
4. Configure Identify, Facility, and Severity and then select OK >> Apply.'
  impact 0.7
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33902r603755_chk'
  tag severity: 'high'
  tag gid: 'V-230972'
  tag rid: 'SV-230972r615886_rule'
  tag stig_id: 'FORE-NM-000460'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-33875r603756_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
