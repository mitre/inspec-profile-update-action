control 'SV-80359' do
  title 'Trend Deep Security must enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.'
  desc 'A mechanism to detect and prevent unauthorized communication flow must be configured or provided as part of the system design. If information flow is not enforced based on approved authorizations, the system may become compromised. Information flow control regulates where information is allowed to travel within a system and between interconnected systems. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the systems or data. 

Application specific examples of enforcement occurs in systems that employ rule sets or establish configuration settings that restrict information system services, or message-filtering capability based on message content (e.g., implementing key word searches or using document characteristics).

Applications providing information flow control must be able to enforce approved authorizations for controlling the flow of information within the system in accordance with applicable policy.'
  desc 'check', %q(Review the Trend Deep Security server configuration to ensure approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies are enforced.

Interview the ISSO in order to identify  all users with permissions to the application.  The ISSO must identify each user along with their assigned role configured for the appropriate information systems allowed.

Verify the information gathered against the application's, "Computer and Group Rights" for each "Role" created  along with the users assigned.

If the information gathered does not match the settings within the application this is a finding.)
  desc 'fix', 'Configure the Trend Deep Security server configuration to enforce approved authorizations for controlling the flow of information within the system based on organization-defined information flow control policies.

Use the Computer and Group Rights panel to confer viewing, editing, deleting, Alert-dismissal, and Event tagging rights to Users in a Role. These rights can apply to all computers and computer groups or they can be restricted to only certain computers.

To restrict access, select the "Selected Computers" radio button and put a check next to the computer groups and computers that Users in this Role will have access to.

Administration >> User Management >> Roles

Select a Role and click Properties >> Computer Rights'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66517r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65869'
  tag rid: 'SV-80359r1_rule'
  tag stig_id: 'TMDS-00-000040'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-71945r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
