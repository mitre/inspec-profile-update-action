control 'SV-17102' do
  title 'A PC communications application is operated with administrative or root level privileges.'
  desc 'PC voice, video, UC, and collaboration communications applications must not be operated in a manner that can compromise the platform if the application itself becomes compromised. One way to mitigate this possibility is to ensure that the application does not require administrative privileges to operate and that it is not operated with privileges that could be used to compromise the platform, other applications, or the network.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:
Ensure PC voice, video, UC, or collaboration communications applications do not require and/or are not configured to operate with administrative privileges.

Determine if the installed PC voice, video, UC, or collaboration communications application(s) requires and/or is configured to operate with administrative privileges. Inspect a random sampling of PC voice, video, UC, or collaboration communications applications to determine if they are configured to operate with administrative privileges. This is a finding if a PC voice, video, UC, or collaboration communications application requires with administrative privileges to operate or if the application or platform is configured such that the application runs with administrative privileges.  Even though a user has administrative privileges, the application should not inherit those privileges and should operate without them.'
  desc 'fix', 'Ensure PC voice, video, UC, or collaboration communications applications do not require and/or are not configured to operate with administrative privileges.

Configure the application and/or platform to not operate with administrative privileges or un-install it. Even though a user has administrative privileges, the application should not inherit those privileges and should operate without them.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17158r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16114'
  tag rid: 'SV-17102r1_rule'
  tag stig_id: 'VVoIP 1715 (GENERAL)'
  tag gtitle: 'Deficient Config: PC Comm App Operating Privilege'
  tag fix_id: 'F-16220r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Compromise of the supporting PC, attached network, and/or network resources.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
