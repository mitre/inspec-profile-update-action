control 'SV-252456' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a communication session. In addition, quickly terminating an idle session or an incomplete logon attempt will also free up resources committed by the managed network element.

SSH options ClientAliveInterval and ClientAliveCountMax are used in combination to monitor SSH connections. If an SSH client is deemed unresponsive, sshd will terminate the connection. An example would be if a client lost network connectivity the SSH connection to the server would be unresponsive, and therefore sshd would terminate the connection after the ClientAliveCountMax and ClientAliveInterval thresholds have been met.

The ClientAliveInterval is a timeout measured in seconds. After which if no data is received from the client, sshd will request a response through the encrypted tunnel from the client. The default is 0, indicating no messages will be sent.

The ClientAliveCountMax is a number of client alive messages that can be sent from the server without receiving a reply from the client. If this threshold is met, sshd will terminate the session. Setting the ClientAliveCountMax to 0 disables connection termination.'
  desc 'check', 'If SSH is not being used, this is Not Applicable.

The SSH daemon "ClientAliveInterval" option must be set correctly. To check the idle timeout setting for SSH sessions, run the following:

/usr/bin/grep -r ^ClientAliveInterval /etc/ssh/sshd_config*

If "ClientAliveInterval" is not configured or has a value of "0", this is a finding.
If "ClientAliveInterval" is not "900" or less, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', %q(To ensure that "ClientAliveInterval" is set correctly, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55912r891340_chk'
  tag severity: 'medium'
  tag gid: 'V-252456'
  tag rid: 'SV-252456r891341_rule'
  tag stig_id: 'APPL-12-000051'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-55862r816181_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
