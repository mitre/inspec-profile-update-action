control 'SV-89523' do
  title 'The MQ Appliance messaging server must use encryption strength in accordance with the categorization of the management data during remote access management sessions.'
  desc 'Remote management access is accomplished by leveraging common communication protocols and establishing a remote connection to the messaging server via a network for the purposes of managing the messaging server. If cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. 

Types of management interfaces utilized by a messaging server include web-based HTTPS interfaces as well as command line-based management interfaces.'
  desc 'check', 'To access the MQ Appliance CLI, enter:
mqcli

config 
crypto
show crypto-mode

If the current setting is set to "permissive", this is a finding.'
  desc 'fix', 'To set management access to the highest encryption strength, enable FIPS 140-2 Level 1 mode at the next reload of the firmware.
Enter the following commands:
config
crypto
crypto-mode-set fips-140-2-l1
Press "Enter"

The following message will appear:
"Crypto Mode Successfully set to fips-140-2-l1 for next boot."'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74849'
  tag rid: 'SV-89523r1_rule'
  tag stig_id: 'MQMH-AS-001320'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag fix_id: 'F-81465r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
