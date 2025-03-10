control 'SV-239554' do
  title 'The SLES for vRealize must enforce SSHv2 for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to SLES for vRealize. Authentication sessions between the authenticator and SLES for vRealize validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any SLES for vRealize account with authorizations of a non-privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify that SLES for vRealize enforces SSHv2 for network access to privileged accounts by running the following command:

Replace [ADDRESS] in the following command with the correct IP address based on the current system configuration. 

# ssh -1 [ADDRESS]

An example of the command usage is as follows:
# ssh -1 localhost

The output must be one of the following items:

Protocol major versions differ: 1 vs. 2

OR

Protocol 1 not allowed in the FIPS mode.

If it does not, this is a finding.

OR 

Verify that the ssh is configured to enforce SSHv2 for network access to privileged accounts by running the following command:

# grep Protocol /etc/ssh/sshd_config

If the result is not "Protocol 2", this is a finding.'
  desc 'fix', "Configure SLES for vRealize to enforce SSHv2 for network access to non-privileged accounts by running the following commands:

# sed -i 's/^.*\\bProtocol\\b.*$/Protocol 2/' /etc/ssh/sshd_config

Restart the ssh service. 

# service sshd restart"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42787r662111_chk'
  tag severity: 'medium'
  tag gid: 'V-239554'
  tag rid: 'SV-239554r662113_rule'
  tag stig_id: 'VROM-SL-000695'
  tag gtitle: 'SRG-OS-000113-GPOS-00058'
  tag fix_id: 'F-42746r662112_fix'
  tag 'documentable'
  tag legacy: ['SV-99229', 'V-88579']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
