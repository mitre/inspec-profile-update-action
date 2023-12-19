control 'SV-215320' do
  title 'AIX must set inactivity time-out on login sessions and terminate all login sessions after 10 minutes of inactivity.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Some maintenance and test tools are either standalone devices with their own operating systems or are applications bundled with an operating system.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at AIX level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that AIX terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.


"
  desc 'check', 'Check if "TMOUT" and "TIMEOUT" environment variables are set to "600" (in seconds) in "/etc/profile" file:

# grep -E " TMOUT|TIMEOUT" /etc/profile
readonly TMOUT=600; readonly TIMEOUT=600; export TMOUT TIMEOUT

If they are not set in "/etc/profile" file, are commented out, or their values are greater than "600", this is a finding.'
  desc 'fix', 'Add or update the following line in the "/etc/profile" file:
readonly TMOUT=600; readonly TIMEOUT=600; export TMOUT TIMEOUT'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16518r294411_chk'
  tag severity: 'medium'
  tag gid: 'V-215320'
  tag rid: 'SV-215320r853481_rule'
  tag stig_id: 'AIX7-00-003003'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-16516r294412_fix'
  tag satisfies: ['SRG-OS-000279-GPOS-00109', 'SRG-OS-000163-GPOS-00072', 'SRG-OS-000126-GPOS-00066']
  tag 'documentable'
  tag legacy: ['V-91493', 'SV-101591']
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002361']
  tag nist: ['MA-4 e', 'SC-10', 'AC-12']
end
