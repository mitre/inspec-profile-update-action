control 'SV-254122' do
  title 'Nutanix AOS must automatically terminate a user session after inactivity time-outs have expired or at shutdown.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance.

"
  desc 'check', 'Confirm Nutanix AOS is configured to auto disconnect remote session to prevent session hijacking.

$ sudo grep -i clientalive /etc/ssh/sshd_config
ClientAliveInterval 600
ClientAliveCountMax 0

If ClientAliveInterval is not "600" and ClientAliveCountMax is not "0", this is a finding.'
  desc 'fix', 'Configure SSH to terminate remote sessions to prevent session hijacking by running the following command.

$ sudo salt-call state.sls security/CVM/sshdCVM

The SSH service will need to be restarted for the changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57607r846452_chk'
  tag severity: 'medium'
  tag gid: 'V-254122'
  tag rid: 'SV-254122r846454_rule'
  tag stig_id: 'NUTX-OS-000050'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-57558r846453_fix'
  tag satisfies: ['SRG-OS-000279-GPOS-00109', 'SRG-OS-000126-GPOS-00066', 'SRG-OS-000163-GPOS-00072']
  tag 'documentable'
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002361']
  tag nist: ['MA-4 e', 'SC-10', 'AC-12']
end
