control 'SV-82575' do
  title 'The A10 Networks ADC must authenticate Network Time Protocol sources.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affected scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the device configuration.

The following command includes an output modifier to display only NTP-related configuration:
show run | include ntp

The output should contain either the "ntp auth-key" command or the "ntp trusted-key" command. 

If it does not, this is a finding.'
  desc 'fix', 'The following command configures NTP authentication:
ntp [auth-key ID-num M string]
This creates an authentication key. For ID-num, enter a value between 1-65535. For string, enter a series of 1-31 alphanumeric characters for the key. This value is stored in the system using the A10 encryption algorithm.

The following command also configures NTP authentication:
ntp [trusted-key ID-num]
This adds an authentication key to the list of trusted keys. For num, enter the identification number of a configured authentication key to add the key to the trusted key list. You can enter more than one number, separated by whitespace, to simultaneously add multiple authentication keys to the trusted key list.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68645r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68085'
  tag rid: 'SV-82575r1_rule'
  tag stig_id: 'AADC-NM-000113'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-74223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
