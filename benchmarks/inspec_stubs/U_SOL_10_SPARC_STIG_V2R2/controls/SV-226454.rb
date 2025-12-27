control 'SV-226454' do
  title 'The root user must not own the logon session for an application requiring a continuous display.'
  desc 'If an application is providing a continuous display and is running with root privileges, unauthorized users could interrupt the process and gain root access to the system.'
  desc 'check', 'If there is an application running on the system continuously in use (such as a network monitoring application), ask the SA what the name of the application is. Execute the following to determine which user owns the process(es) associated with the application. If the owner is root, this is a finding.

# ps -ef | more'
  desc 'fix', 'Configure the system so the owner of a session requiring a continuous screen display, such as a network management display, is not root. Ensure the display is also located in a secure, controlled access area. Document and justify this requirement.  Ensure the terminal and keyboard for the display (or workstation) are secure from all but authorized personnel by maintaining them in a secure area, in a locked cabinet where a swipe card, or other positive forms of identification, must be used to gain entry.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36378r602737_chk'
  tag severity: 'medium'
  tag gid: 'V-226454'
  tag rid: 'SV-226454r603265_rule'
  tag stig_id: 'GEN000520'
  tag gtitle: 'SRG-OS-000326'
  tag fix_id: 'F-36342r602738_fix'
  tag 'documentable'
  tag legacy: ['V-769', 'SV-769']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
