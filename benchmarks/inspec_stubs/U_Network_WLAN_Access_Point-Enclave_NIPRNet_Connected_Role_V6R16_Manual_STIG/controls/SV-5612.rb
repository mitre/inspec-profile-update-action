control 'SV-5612' do
  title 'The network devices must be configured to timeout after 60 seconds or less for incomplete or broken SSH sessions.'
  desc 'An attacker may attempt to connect to the device using SSH by guessing the authentication method, encryption algorithm, and keys. Limiting the amount of time allowed for authenticating and negotiating the SSH session reduces the window of opportunity for the malicious user attempting to make a connection to the network device.'
  desc 'check', 'Review the configuration and verify the timeout is set for 60 seconds or less. The SSH service terminates the connection if protocol negotiation (that includes user authentication) is not complete within this timeout period.

If the device is not configured to drop broken SSH sessions after 60 seconds, this is a finding.'
  desc 'fix', 'Configure the network devices so it will require a secure shell timeout of 60 seconds or less.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  ref 'DPMS Target Network Appliance'
  tag check_id: 'C-3534r6_chk'
  tag severity: 'medium'
  tag gid: 'V-5612'
  tag rid: 'SV-5612r4_rule'
  tag stig_id: 'NET1645'
  tag gtitle: 'SSH session timeout is not 60 seconds or less.'
  tag fix_id: 'F-5523r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
