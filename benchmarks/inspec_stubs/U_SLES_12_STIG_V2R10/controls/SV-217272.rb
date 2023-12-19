control 'SV-217272' do
  title 'The SUSE operating system SSH daemon must be configured with a timeout interval.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the SUSE operating system level, and deallocating networking assignments at the application level if multiple application sessions are using a single SUSE operating system-level network connection. This does not mean that the SUSE operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the SUSE operating system SSH daemon is configured to timeout idle sessions.

Check that the "ClientAliveInterval" parameter is set to a value of "600" with the following command:

# sudo grep -i clientalive /etc/ssh/sshd_config
ClientAliveInterval 600

If "ClientAliveInterval" is not set to "600" in "/etc/ssh/sshd_config", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon to timeout idle sessions.

Add or modify (to match exactly) the following line in the "/etc/ssh/sshd_config" file:

ClientAliveInterval 600

The SSH daemon must be restarted in order for any changes to take effect.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18500r369972_chk'
  tag severity: 'medium'
  tag gid: 'V-217272'
  tag rid: 'SV-217272r854157_rule'
  tag stig_id: 'SLES-12-030190'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-18498r369973_fix'
  tag satisfies: ['SRG-OS-000126-GPOS-00066', 'SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['SV-92155', 'V-77459']
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002361']
  tag nist: ['MA-4 e', 'SC-10', 'AC-12']
end
