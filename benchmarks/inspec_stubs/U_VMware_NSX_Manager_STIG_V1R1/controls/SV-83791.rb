control 'SV-83791' do
  title 'The NSX vCenter must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 
 
One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised. 
 
This requirement does not include emergency administration accounts which are meant for access to the network device in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the value of the "Maximum lifetime" setting. 

If the "Maximum lifetime" policy is not set to "60", this is a finding.'
  desc 'fix', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

Click "Edit". Enter "60" into the "Maximum lifetime" setting and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69187'
  tag rid: 'SV-83791r1_rule'
  tag stig_id: 'VNSX-ND-000065'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-75373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
