control 'SV-93227' do
  title 'The admin password for the McAfee MOVE AV Security Virtual Machine (SVM) must be changed from the default.'
  desc 'The preconfigured Security Virtual Appliance (SVA) comes with a default password for the "SVAadmin" account. This account has root privileges to the Linux operating system of the appliance. By not changing the password from the default, the appliance will be subject to access by unauthorized individuals.'
  desc 'check', 'If the McAfee SVM was deployed manually, physically log into the McAfee SVM and confirm password has been changed from default.

If the password has not been changed from the default, this is a finding.

If the McAfee SVM was deployed with VMware vCNS or VMWare NSX, access the McAfee ePO console. 

From the Menu, select Automation >> MOVE AntiVirus Deployment.

Under General >> General Configuration >> SVM Configuration (Agentless Only), verify the "Password" shows as configured. It will be masked.

Verify with the System Administrator that the password has been changed from the default password. 

If "Password" does not show as configured and has not been changed from the default password, this is a finding.'
  desc 'fix', 'If the McAfee SVM was deployed manually, physically log into the McAfee SVM and change the password from the default.

If the McAfee SVM was deployed with VMware vCNS or VMWare NSX, access the McAfee ePO console. 

From the Menu, select Automation >> MOVE AntiVirus Deployment.

Under General >> General Configuration >> SVM Configuration (Agentless Only), populate the "Password" with a unique password. Confirm the password.

Click "Save".'
  impact 0.7
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78083r1_chk'
  tag severity: 'high'
  tag gid: 'V-78521'
  tag rid: 'SV-93227r1_rule'
  tag stig_id: 'MV45-GEN-000003'
  tag gtitle: 'MV45-GEN-000003'
  tag fix_id: 'F-85255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
