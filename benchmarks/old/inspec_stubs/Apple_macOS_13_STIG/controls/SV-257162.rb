control 'SV-257162' do
  title 'The macOS system must be configured with the SSH daemon ClientAliveInterval option set to 900 or less.'
  desc 'SSH options ClientAliveInterval and ClientAliveCountMax are used in combination to monitor SSH connections. If an SSH client is deemed unresponsive, sshd will terminate the connection. An example would be if a client lost network connectivity the SSH connection to the server would be unresponsive and therefore sshd would terminate the connection after the ClientAliveCountMax and ClientAliveInterval thresholds have been met.

The ClientAliveInterval is a timeout measured in seconds. After which if no data is received from the client, sshd will request a response through the encrypted tunnel from the client. The default is "0", indicating no messages will be sent.

The ClientAliveCountMax is the number of client alive messages that can be sent from the server without receiving a reply from the client. If this threshold is met, sshd will terminate the session. Setting the ClientAliveCountMax to "0" disables connection termination.'
  desc 'check', 'If SSH is not being used, this is not applicable.

Verify the macOS system is configured with the SSH daemon "ClientAliveInterval" option set to "900" or less with the following command:

/usr/bin/grep -r ^ClientAliveInterval /etc/ssh/sshd_config*

If "ClientAliveInterval" is not configured or has a value of "0", this is a finding.

If "ClientAliveInterval" is not "900" or less, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', %q(Configure the macOS system to set the SSH daemon "ClientAliveInterval" option to "900" with the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 900/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60847r905117_chk'
  tag severity: 'medium'
  tag gid: 'V-257162'
  tag rid: 'SV-257162r922873_rule'
  tag stig_id: 'APPL-13-000051'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-60788r905118_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
