control 'SV-89699' do
  title 'SSH CLI access to the MQ Appliance management interface must be restricted to approved management workstations.'
  desc 'The approved method for authenticating to systems is via two-factor authentication. Two-factor authentication is defined as using something you have (e.g., CAC or token) and something you know (e.g., PIN). The SSH CLI in MQ does not have the native ability to use multifactor authentication. This increases the risk of user account compromise. Restricting access to the MQ SSH management interface helps to mitigate this risk. Access must be restricted to only those management workstations or networks that require access.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. 
Go to the Network icon. Select Management >> SSH Service.
Click "edit" next to the Access control list field.
View the SSH ACL and obtain the list of authorized addresses. 

Ask the administrator for the list of approved addresses. If an authorized management network is in place, the SSH ACL can include a range of addresses within the authorized management network.

If a firewall is used to isolate SSH traffic, request the IP addresses of the MQ appliance and the relevant firewall ruleset.

If SSH traffic is not restricted to the list of approved addresses, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. 
Go to Network icon. Select Management >> SSH Service.
Click "edit" next to the Access control list field.
Edit the SSH ACL and add authorized workstations or management network segment.

For a firewall solution, isolate the MQ SSH network interface behind the firewall and apply firewall rules to limit SSH access to only authorized management workstations or networks.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75025'
  tag rid: 'SV-89699r1_rule'
  tag stig_id: 'MQMH-ND-001530'
  tag gtitle: 'SRG-APP-000408-NDM-000314'
  tag fix_id: 'F-81639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
