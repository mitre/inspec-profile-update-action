control 'SV-203659' do
  title 'The operating system must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify the operating system terminates all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements. 

If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3784r793161_chk'
  tag severity: 'medium'
  tag gid: 'V-203659'
  tag rid: 'SV-203659r793162_rule'
  tag stig_id: 'SRG-OS-000163-GPOS-00072'
  tag gtitle: 'SRG-OS-000163'
  tag fix_id: 'F-3784r793151_fix'
  tag 'documentable'
  tag legacy: ['SV-71125', 'V-56865']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
