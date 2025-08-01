control 'SV-215290' do
  title 'AIX must config the SSH idle timeout interval.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance.
"
  desc 'check', 'Run the following command to check if "ClientAliveInterval" and "ClientAliveCountMax" are set for SSH server:

# grep -E "^ClientAliveInterval|^ClientAliveCountMax" /etc/ssh/sshd_config
ClientAliveInterval 600
ClientAliveCountMax 0

If "ClientAliveCountMax" is not set or its value is not "0", this is a finding.

If "ClientAliveInterval" is not set, or its value is not "600" (10-minutes) or less, this is a finding.'
  desc 'fix', 'Add or update the following lines in "/etc/ssh/sshd_config":
ClientAliveInterval 600 
ClientAliveCountMax 0

Restart sshd:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16488r648725_chk'
  tag severity: 'medium'
  tag gid: 'V-215290'
  tag rid: 'SV-215290r648727_rule'
  tag stig_id: 'AIX7-00-002105'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-16486r648726_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072']
  tag 'documentable'
  tag legacy: ['V-91491', 'SV-101589']
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
