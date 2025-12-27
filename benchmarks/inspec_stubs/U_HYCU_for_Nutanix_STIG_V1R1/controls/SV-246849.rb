control 'SV-246849' do
  title 'The network device must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'The use of SSH-2 protocol for network/remote access prevents replay attacks. The SSH-2 protocol is the standard for the SSH daemon in CentOS 8 used by HYCU.

To determine the SSH version in use, log on to the HYCU console and execute the following command:
ssh -v localhost

If the output does not show remote protocol version 2.0 in use, this is a finding.

HYCU web access uses TLS, which addresses this threat. HYCU web access cannot be configured not to use TLS.'
  desc 'fix', 'Log on to the HYCU console and configure SSH to use the SSH-2 protocol by editing the Protocol variable in the file "/etc/ssh/sshd_config".'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50281r768209_chk'
  tag severity: 'medium'
  tag gid: 'V-246849'
  tag rid: 'SV-246849r768211_rule'
  tag stig_id: 'HYCU-IA-000001'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-50235r768210_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
