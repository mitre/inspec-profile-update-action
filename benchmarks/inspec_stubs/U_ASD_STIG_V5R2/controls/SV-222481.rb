control 'SV-222481' do
  title 'The application must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.  In addition, attackers often manipulate logs to hide or obfuscate their activity.

The goal is to off-load application logs to a separate server as quickly and efficiently as possible so as to mitigate these risks.  

A centralized logging solution offering applications an enterprise designed and managed logging capability which is the desired solution.

However, when a centralized logging solution is not an option due to the operational environment or other situations where the risk has been officially recognized and accepted, off-loading is a common process utilized to address this type of scenario.'
  desc 'check', 'Review application documentation and interview application administrator.  Identify log functionality and locations of log files.  Obtain risk acceptance documentation and task scheduling information.

If the application is configured to utilize a centralized logging solution, this requirement is not applicable.

Evaluate log management processes and determine if there are automated tasks that move the logs off of the system hosting the application.   

Verify automated tasks are performed on an ISSO approved schedule (hourly, daily etc.).  Automation can be via scripting, log management oriented tools or other automated means.

Review risk acceptance documentation for not utilizing a centralized logging solution.

If the logs are not automatically moved off the system as per approved schedule, or if there is no formal risk acceptance documentation, this is a finding.'
  desc 'fix', 'Configure the application to off-load audit records onto a different system as per approved schedule.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24151r493351_chk'
  tag severity: 'medium'
  tag gid: 'V-222481'
  tag rid: 'SV-222481r849435_rule'
  tag stig_id: 'APSC-DV-001070'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-24140r493352_fix'
  tag 'documentable'
  tag legacy: ['SV-84067', 'V-69445']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
