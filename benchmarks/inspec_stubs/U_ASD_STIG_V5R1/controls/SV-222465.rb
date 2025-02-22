control 'SV-222465' do
  title 'The application must generate audit records when successful/unsuccessful accesses to objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Application objects are system or application components that comprise the application. This includes but is not limited to; application files, folders, processes and modules.

This requirement is not intended to force the use of debug logging which would be used for troubleshooting or forensic actions; rather it is intended to assure the application strikes a balance when auditing access to application objects and logs normal and potentially abnormal application activity.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the application documentation and interview the application administrator to identify log locations.

Access the application logs.

Review the logs and identify if the application is logging both successful and unsuccessful access to application objects such as files, folders, processes, or application modules and sub components, or systems.

If the application does not log application object access, this is a finding.'
  desc 'fix', 'Configure the application to log successful and unsuccessful access to application objects.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24135r493303_chk'
  tag severity: 'medium'
  tag gid: 'V-222465'
  tag rid: 'SV-222465r508029_rule'
  tag stig_id: 'APSC-DV-000860'
  tag gtitle: 'SRG-APP-000507'
  tag fix_id: 'F-24124r493304_fix'
  tag 'documentable'
  tag legacy: ['SV-84033', 'V-69411']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
