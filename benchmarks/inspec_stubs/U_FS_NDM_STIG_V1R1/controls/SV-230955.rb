control 'SV-230955' do
  title 'Forescout must generate log records for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Verify the syslog triggers are configured in accordance with SSP requirements.

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers.
3. Ensure the proper NAC events and System Logs and Events are selected in compliance with the SSP. 

If Forescout does not generate log records for a locally developed list of auditable events, this is a finding.'
  desc 'fix', 'Configure Forescout auditing messages to ensure auditing is comprehensible for monitoring and analysis. 

1. Log on to Forescout Administrator UI with admin or operator credentials. 
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Syslog Triggers. 
3. Ensure the proper NAC events and System Logs and Events are selected.'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33885r603704_chk'
  tag severity: 'medium'
  tag gid: 'V-230955'
  tag rid: 'SV-230955r615886_rule'
  tag stig_id: 'FORE-NM-000280'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-33858r603705_fix'
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-000366']
  tag nist: ['AU-12 a', 'CM-6 b']
end
