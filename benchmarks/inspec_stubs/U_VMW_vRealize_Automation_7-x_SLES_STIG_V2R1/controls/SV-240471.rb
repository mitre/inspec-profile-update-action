control 'SV-240471' do
  title 'The SLES for vRealize must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for user sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Check for the existence of the /etc/profile.d/tmout.sh file:

# ls -al /etc/profile.d/tmout.sh

Check for the presence of the "TMOUT" variable:

# grep TMOUT /etc/profile.d/tmout.sh

The value of "TMOUT" should be set to "900" seconds (15 minutes).

If the file does not exist, or the "TMOUT" variable is not set to "900", this is a finding.'
  desc 'fix', 'Ensure the file exists and is owned by "root". If the files does not exist, use the following commands to create the file:

# touch /etc/profile.d/tmout.sh
# chown root:root /etc/profile.d/tmout.sh
# chmod 644 /etc/profile.d/tmout.sh

Edit the file /etc/profile.d/tmout.sh, and add the following lines: 

TMOUT=900
readonly TMOUT
export TMOUT
mesg n 2>/dev/null'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43704r671152_chk'
  tag severity: 'medium'
  tag gid: 'V-240471'
  tag rid: 'SV-240471r671395_rule'
  tag stig_id: 'VRAU-SL-000795'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-43663r671153_fix'
  tag 'documentable'
  tag legacy: ['SV-100369', 'V-89719']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
