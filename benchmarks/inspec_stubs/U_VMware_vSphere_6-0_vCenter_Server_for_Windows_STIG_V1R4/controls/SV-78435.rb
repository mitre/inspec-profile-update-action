control 'SV-78435' do
  title 'The system must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  View the value of the "Maximum lifetime" setting.

If the "Maximum lifetime" policy is not set to 60, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  Click "Edit" and enter "60" into the "Maximum lifetime" setting and click "OK".'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63945'
  tag rid: 'SV-78435r1_rule'
  tag stig_id: 'VCWN-06-000003'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-69873r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
