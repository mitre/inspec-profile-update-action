control 'SV-228678' do
  title 'The Palo Alto Networks security platform must authenticate Network Time Protocol sources.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server.  This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affected scheduled actions.  NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Go to Device >> Setup >> Services
In the "Services" window, the Primary NTP Server Authentication Type and Secondary NTP Server Authentication Type must be either Symmetric Key or Autokey. If the "Primary NTP Server Authentication Type" and "Secondary NTP Server Authentication Type" fields are "none", this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Services
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Services" window, in the NTP tab, in the "Primary NTP Server Address" field and the "Secondary NTP Server Address" field, enter the IP address or hostname of the NTP servers.

In the "Authentication Type" field, select one of the following:
Symmetric Key; this option uses symmetric key exchange, which are shared secrets. Enter the key ID, algorithm, authentication key, and confirm the authentication key; for the algorithm, select "SHA1".
Autokey; this option uses auto key, or public key cryptography.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30913r513637_chk'
  tag severity: 'medium'
  tag gid: 'V-228678'
  tag rid: 'SV-228678r856018_rule'
  tag stig_id: 'PANW-NM-000145'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-30890r513638_fix'
  tag 'documentable'
  tag legacy: ['SV-77275', 'V-62785']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
