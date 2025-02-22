control 'SV-218224' do
  title 'The root user must not own the logon session for an application requiring a continuous display.'
  desc 'If an application is providing a continuous display and is running with root privileges, unauthorized users could interrupt the process and gain root access to the system.'
  desc 'check', 'If there is an application running on the system continuously in use (such as a network monitoring application), ask the SA what the name of the application is.
Verify documentation exists for the requirement and justification of the application. If no documentation exists, this is a finding.
Execute "ps -ef | more" to determine which user owns the process(es) associated with the application. If the owner is root, this is a finding.'
  desc 'fix', 'Configure the system so the owner of a session requires a continuous screen display, such as a network management display, is not root. Ensure the display is also located in a secure, controlled access area. Document and justify this requirement and ensure the terminal and keyboard for the display (or workstation) are secure from all but authorized personnel by maintaining them in a secure area, in a locked cabinet where a swipe card, or other positive forms of identification, must be used to gain entry.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19699r561413_chk'
  tag severity: 'medium'
  tag gid: 'V-218224'
  tag rid: 'SV-218224r603259_rule'
  tag stig_id: 'GEN000520'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19697r561414_fix'
  tag 'documentable'
  tag legacy: ['V-769', 'SV-63649']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
