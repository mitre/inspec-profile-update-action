control 'SV-240961' do
  title 'The vAMI must have PAM logging enabled.'
  desc 'Determining when a user has accessed the management interface is important to determine the timeline of events when a security incident occurs. Generating these events, especially if the management interface is accessed via a stateless protocol like HTTP, the log events will be generated when the user performs a logon (start) and when the user performs a logoff (end). Without these events, the user and later investigators cannot determine the sequence of events and therefore cannot determine what may have happened and by whom it may have been done. The generation of start and end times within log events allow the user to perform their due diligence in the event of a security breach.'
  desc 'check', 'At the command prompt, execute the following command:

ls /etc/pam_debug

If the /etc/pam_debug file does not exist, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

touch /etc/pam_debug'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44194r676048_chk'
  tag severity: 'medium'
  tag gid: 'V-240961'
  tag rid: 'SV-240961r879876_rule'
  tag stig_id: 'VRAU-VA-000620'
  tag gtitle: 'SRG-APP-000505-AS-000230'
  tag fix_id: 'F-44153r676049_fix'
  tag 'documentable'
  tag legacy: ['SV-100917', 'V-90267']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
