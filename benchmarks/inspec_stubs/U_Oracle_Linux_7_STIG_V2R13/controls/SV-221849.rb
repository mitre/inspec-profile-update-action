control 'SV-221849' do
  title 'The Oracle Linux operating system must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes.

Check for the value of the "ClientAliveInterval" keyword with the following command:

     # grep -iw clientaliveinterval /etc/ssh/sshd_config

     ClientAliveInterval 600

If "ClientAliveInterval" is not configured, is commented out, or has a value of "0", this is a finding.

If "ClientAliveInterval" has a value that is greater than "600" and is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Note: This setting must be applied in conjunction with OL07-00-040340 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has become unresponsive.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

     ClientAliveInterval 600

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23564r917855_chk'
  tag severity: 'medium'
  tag gid: 'V-221849'
  tag rid: 'SV-221849r917857_rule'
  tag stig_id: 'OL07-00-040320'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-23553r917856_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['SV-108541', 'V-99437']
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
