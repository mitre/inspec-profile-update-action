control 'SV-214348' do
  title 'The Apache web server must not impede the ability to write specified log record content to an audit log server.'
  desc 'Writing events to a centralized management audit system offers many benefits to the enterprise over having dispersed logs. Centralized management of audit records and logs provides for efficiency in maintenance and management of records, enterprise analysis of events, and backup and archiving of event records enterprise-wide. The web server and related components are required to be capable of writing logs to centralized audit log servers.'
  desc 'check', 'Work with the SIEM administrator to determine current security integrations. 

If the SIEM is not integrated with security, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to integrate with an organizations security infrastructure.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15560r277547_chk'
  tag severity: 'medium'
  tag gid: 'V-214348'
  tag rid: 'SV-214348r505936_rule'
  tag stig_id: 'AS24-W1-000720'
  tag gtitle: 'SRG-APP-000358-WSR-000063'
  tag fix_id: 'F-15558r277548_fix'
  tag 'documentable'
  tag legacy: ['SV-102537', 'V-92449']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
