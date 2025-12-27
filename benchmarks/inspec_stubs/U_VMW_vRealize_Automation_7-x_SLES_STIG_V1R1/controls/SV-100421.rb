control 'SV-100421' do
  title 'The SLES for vRealize must automatically terminate a user session after inactivity time-outs have expired or at shutdown.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
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
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89463r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89771'
  tag rid: 'SV-100421r1_rule'
  tag stig_id: 'VRAU-SL-000960'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-96513r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
