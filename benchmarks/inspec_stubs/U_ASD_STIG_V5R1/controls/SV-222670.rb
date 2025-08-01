control 'SV-222670' do
  title 'The application must provide notifications or alerts when product update and security related patches are available.'
  desc 'An application vulnerability management and update process must be in place to notify and provide users and administrators with a means of obtaining security patches and updates for the application.

An important part of the maintenance phase of an application is managing vulnerabilities for updated versions of the application after the application is released.  When a security flaw is discovered in an application deployed in a production environment, notification to the user community must take place as quickly as possible. 

This notification should be planned for in the design phase of the application. This notification should be a warning of any potential risks to the application or data. A notification mechanism will be established to notify users of the vulnerability and the potential risks, the availability of a solution, and/or potential mitigations reducing risks to the application.'
  desc 'check', 'Review the components of the application.  Interview the application administrator.

Have the application administrator demonstrate the application notification process that occurs when a security patch or product update is available.

The process must include a brief description of the issue and any potential risks related to the issue.

The process must also include information regarding the availability of the patch or update and how it can be obtained as well as any potential mitigations that can be utilized in the interim.

If there is no application security patch or update notification process, this is a finding.

If the application notification process does not include a brief description, information on risks, how to obtain the patch or update and any potential mitigations, this is a finding.'
  desc 'fix', 'Provide a distribution mechanism for obtaining updates to the application.

Include a description of the issue, a summary of risk as well as potential mitigations and how to obtain the update.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24340r493918_chk'
  tag severity: 'low'
  tag gid: 'V-222670'
  tag rid: 'SV-222670r508029_rule'
  tag stig_id: 'APSC-DV-003345'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24329r493919_fix'
  tag 'documentable'
  tag legacy: ['V-70419', 'SV-85041']
  tag cci: ['CCI-001286', 'CCI-000366']
  tag nist: ['SI-5 b', 'CM-6 b']
end
