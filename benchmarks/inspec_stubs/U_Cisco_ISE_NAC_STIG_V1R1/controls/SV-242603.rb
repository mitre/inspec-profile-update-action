control 'SV-242603' do
  title 'Before establishing a connection with a Network Time Protocol (NTP) server, the Cisco ISE must authenticate using a bidirectional, cryptographically based authentication method that uses a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the NTP server.'
  desc 'If the NTP server is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.

Currently, AES block cipher algorithm is approved for use in DoD for both applying cryptographic protection (e.g., encryption) and removing or verifying the protection that was previously applied (e.g., decryption). NTP devices use MD5 authentication keys. The MD5 algorithm is not specified in either the FIPS or NIST recommendation. However, MD5 is preferred to no authentication at all.

The trusted-key statement permits authenticating NTP servers. The product must be configured to support separate keys for each NTP server. Severs should have a PKI device certificate involved for use in the device authentication process.'
  desc 'check', 'Verify NTP setting to ensure NTP will be authenticated. 

From the CLI:
1. Type "show running-config | in ntp".
2. Verify that each defined NTP server has a key on the same line defining the server and make a note of the key number.
3. Verify that each NTP Key number used is created.

If there is an NTP source without an NTP key defined and it is a domain controller, this is not a finding as Windows server does not support NTP keys. 

If there are any other NTP sources that do not use a defined key, this is a finding. 

Note: Each ISE node must be individually checked as NTP settings are local to each appliance.
Note: There are NTP settings in the GUI; however, it is recommended to use the NTP setting solely in CLI to prevent issues.'
  desc 'fix', 'Configure the NTP server to be authenticated. 

From the CLI:
1. Type "configure terminal".
2. Define an NTP authentication key "ntp authentication-key <KEY Number> md5 plain <NTP KEY>.
3. Define an NTP server and associate it with the configured NTP key "ntp server <IP> key <KEY Number>".
4. Type "exit" and press enter.
5. Type "write memory" and press "Enter".

If a domain controller is used for NTP, then a key cannot be used as Windows servers do not support NTP keys. 

Note: Each ISE node must be individually checked as NTP settings are local to each appliance.
Note: There are NTP settings in the GUI; however, it is recommended to use the NTP setting solely in CLI to prevent issues.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45878r714117_chk'
  tag severity: 'medium'
  tag gid: 'V-242603'
  tag rid: 'SV-242603r714119_rule'
  tag stig_id: 'CSCO-NC-000290'
  tag gtitle: 'SRG-NET-000550-NAC-002470'
  tag fix_id: 'F-45835r714118_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
