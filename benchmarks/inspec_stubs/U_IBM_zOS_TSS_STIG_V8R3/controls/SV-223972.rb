control 'SV-223972' do
  title 'CA-TSS VTHRESH Control Option values specified must be set to (10,NOT,CAN).'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'From the ISPF Control Shell enter:
TSS MODIFY STATUS

If the VTHRESH Control Option values are not set to "VTHRRESH(10,NOT,CAN)", this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting to "VTHRESH(10,NOT,CAN)", and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25645r516315_chk'
  tag severity: 'medium'
  tag gid: 'V-223972'
  tag rid: 'SV-223972r561402_rule'
  tag stig_id: 'TSS0-ES-000990'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-25633r516316_fix'
  tag 'documentable'
  tag legacy: ['V-98651', 'SV-107755']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
