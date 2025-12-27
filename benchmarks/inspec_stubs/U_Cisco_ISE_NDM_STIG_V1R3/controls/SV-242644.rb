control 'SV-242644' do
  title 'The Cisco ISE must authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', '1. View the status of the Network Translation Protocol (NTP) associations.
show ntp
2. Verify a primary and secondary ntp server address is configured.

If the Cisco ISE is not configured to synchronize internal information system clocks using redundant authoritative time sources, this is a finding.'
  desc 'fix', '1. Choose Administration >> System >> Settings >> System Time.
2.  Enter unique IP addresses (IPv4/IPv6/FQDN) for the NTP servers.
3.  Check the "Only allow authenticated NTP servers" check box if you want to restrict Cisco ISE to use only authenticated NTP servers to keep system and network time. DoD requires NTP authentication where available, so configure the NTP server using private keys. Click the "NTP Authentication Keys" tab and specify one or more authentication keys if any of the servers that you specify requires authentication via an authentication key, as follows:
4. Click "Add".
5. Enter the necessary Key ID and Key Value. Specify whether the key in question is trusted by activating or deactivating the Trusted Key option, and click "OK". The Key ID field supports numeric values between 1 and 65535, and the Key Value field supports up to 15 alphanumeric characters.
6. Return to the NTP Server Configuration tab when finished entering the NTP Server Authentication Keys.
7. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45919r714240_chk'
  tag severity: 'medium'
  tag gid: 'V-242644'
  tag rid: 'SV-242644r714242_rule'
  tag stig_id: 'CSCO-NM-000390'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-45876r714241_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
