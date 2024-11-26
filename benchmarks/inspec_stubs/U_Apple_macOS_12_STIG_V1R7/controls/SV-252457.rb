control 'SV-252457' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveCountMax option set to 1.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.

SSH options ClientAliveInterval and ClientAliveCountMax are used in combination to monitor SSH connections. If an SSH client is deemed unresponsive, sshd will terminate the connection. An example would be if a client lost network connectivity the SSH connection to the server would be unresponsive, and therefore sshd would terminate the connection after the ClientAliveCountMax and ClientAliveInterval thresholds have been met.

The ClientAliveInterval is a timeout measured in seconds. After which if no data is received from the client, sshd will request a response through the encrypted tunnel from the client. The default is 0, indicating no messages will be sent.

The ClientAliveCountMax is a number of client alive messages that can be sent from the server without receiving a reply from the client. If this threshold is met, sshd will terminate the session. Setting the ClientAliveCountMax to 0 disables connection termination.'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

The SSH daemon "ClientAliveCountMax" option must be set correctly. To verify the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/grep -r ^ClientAliveCountMax /etc/ssh/sshd_config*

If the setting is not "ClientAliveCountMax 1", this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', %q(To ensure that the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 1/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55913r891342_chk'
  tag severity: 'medium'
  tag gid: 'V-252457'
  tag rid: 'SV-252457r891344_rule'
  tag stig_id: 'APPL-12-000052'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-55863r891343_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
