control 'SV-228855' do
  title 'The Palo Alto Networks security, if used as a TLS gateway/decryption point or VPN concentrator, must provide the capability to immediately disconnect or disable remote access to the information system.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking place would not be immediately stopped.

Remote access functionality must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The remote access functionality may implement features such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack.

If the Palo Alto Networks security platform is used as a TLS gateway/decryption point or VPN concentrator, configure the device to deny decrypted traffic that violates the enclave or system policies. For each type of SSL/TLS traffic that is decrypted, the resulting traffic must be inspected and filtered.'
  desc 'check', 'If the Palo Alto Networks security platform is not used as a TLS gateway/decryption point or VPN concentrator, this is not applicable.

Go to Policies >> Decryption
Note each configured decryption policy.
Go to Policies >> Security
View the configured security policies.
If there is a decryption policy that does not have a corresponding security policy, this is a finding.

The matching policy may not be obvious, and it may be necessary for the Administrator to identify the corresponding security policy.
Select the Security Policy Rules applied to the decrypted traffic. If it allows traffic that is prohibited, this is a finding.'
  desc 'fix', %q(These instructions explain the steps involved but do not provide specific details since the exact policies and expected traffic are not known.

Go to Policies >> Security
Select "Add".
In the "Security Policy Rule" window, complete the required fields.
Configure the Security Policy in accordance with the enclave's or system's policy for the resulting decrypted traffic.
For any traffic that violates the enclave policy, configure the Security Policy rule to deny the traffic.
In the "Security Policy Rule" window, in the "Actions" tab, in the "Action Setting" section, select "deny".
For any traffic that is allowed, configure the Security Policy Rule to allow the traffic and apply Antivirus and Vulnerability Protection Profiles. 
In the "Security Policy Rule" window, in the "Actions" tab, in the "Action Setting" section, select "allow".
In the "Security Policy Rule" window, in the "Actions" tab, in the "Profiles Setting" section, select the necessary Profiles.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31090r513860_chk'
  tag severity: 'medium'
  tag gid: 'V-228855'
  tag rid: 'SV-228855r557387_rule'
  tag stig_id: 'PANW-AG-000079'
  tag gtitle: 'SRG-NET-000314-ALG-000013'
  tag fix_id: 'F-31067r513861_fix'
  tag 'documentable'
  tag legacy: ['SV-77081', 'V-62591']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
