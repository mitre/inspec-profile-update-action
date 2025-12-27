control 'SV-16775' do
  title 'ESX Server is not authenticating the time source with a hashing algorithm.'
  desc 'Since NTP is used to ensure accurate log file timestamps for information, NTP could pose a security risk if a malicious user were able to falsify NTP information. Implementing authentication between NTP peers can mitigate this risk. When hashing authentication is enforced, there is a greater level of assurance that NTP updates are from a trusted source.'
  desc 'check', 'NTP authentication is used by time clients to authenticate the time server to prevent rogue server intervention. NTP authentication is based on encrypted keys. A key is encrypted and sent to the client by the server, where it is unencrypted and checked against the client key to ensure a match.

NTP keys are stored in the ntp.keys file in the following format: 
Key-number M Key (The M stands for MD5 encryption), e.g.: 
1 M secret 
5 M RaBBit 
7 M TiMeLy 
10 M MYKEY 

The NTP configuration file ntp.conf specifies which of the keys are trusted. Any keys specified in the keys file but not trusted will not be used for authentication, e.g.: 

trustedkey 1 7 10

In this example, 5 is not trusted, only 1, 7, and 10 above.

1. On the ESX Server service console perform the following:

# cat /etc/ntp.conf

Review the configuration file to verify that the following are uncommented:
authenticate yes
….
keys /etc/ntp/keys

If these are commented out, this is a finding.

2. Next verify that the trusted keys are configured in the ntp.conf file.
trustedkey <number>

If none are listed, this is a finding.

3. Next, review the keys file located at /etc/ntp/keys by performing the following:

# cat /etc/ntp/keys

Verify that keys are listed in the keys file.  File should look similar to the following:
5 M RaBBit 7 M TiMeLy 10 M MYKEY 

If no keys are configured here, this is a finding.'
  desc 'fix', 'Configure the ESX Server to authenticate the time source.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15836'
  tag rid: 'SV-16775r1_rule'
  tag stig_id: 'ESX0400'
  tag gtitle: 'Time source not authenticated with hash algorithm.'
  tag fix_id: 'F-15787r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
