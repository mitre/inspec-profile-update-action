control 'SV-234200' do
  title 'The FortiGate device must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', "Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show full-configuration system global | grep -i 'tls\\|ssh-v'
The output should be:  
           # set admin-https-ssl-versions tlsv1-2 tlsv1-3
           # set admin-ssh-v1 disable
           # set ssl-min-proto-version TLSv1-2          
      #end

If admin-https-ssl-versions is not set to tlsv1-2 tlsv1-3 or admin-ssh-v1 is enable, this is a finding."
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system global
          # set admin-https-ssl-versions tlsv1-2 tlsv1-3
          # set admin-ssh-v1 disable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37385r611787_chk'
  tag severity: 'medium'
  tag gid: 'V-234200'
  tag rid: 'SV-234200r879597_rule'
  tag stig_id: 'FGFW-ND-000205'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-37350r611788_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
