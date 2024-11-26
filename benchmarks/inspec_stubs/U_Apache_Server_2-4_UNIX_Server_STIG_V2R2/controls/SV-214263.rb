control 'SV-214263' do
  title 'The Apache web server must not impede the ability to write specified log record content to an audit log server.'
  desc 'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.'
  desc 'check', 'Work with SIEM administrator to determine audit configurations. 

If there is a setting within the SIEM that could impede the ability to write specific log record content, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to  allow the ability to write specified log record content to an audit log server.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15477r277049_chk'
  tag severity: 'medium'
  tag gid: 'V-214263'
  tag rid: 'SV-214263r612240_rule'
  tag stig_id: 'AS24-U1-000720'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-15475r277050_fix'
  tag 'documentable'
  tag legacy: ['SV-102805', 'V-92717']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
