control 'SV-80393' do
  title 'Trend Deep Security must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Review the Trend Deep Security server to ensure the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments, are prohibited or restricted.

Review the firewall policy for approved ports, protocols and services associated within a defined group or a selected computer by selecting Computers, on the top menu bar.

Choose the appropriate group and within the main page, select a computer for review.

Double-click the selected computer and click "Firewall".
  
Verify the following settings are enabled:

Configuration: Inherit or On
State: Activated
Firewall Stateful Configurations: Inherited (If managed through a group policy)
Assigned Firewall Rules: (are configured in accordance with local security policy) 

If the options identified are not set or configured in accordance with local policy, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.

From the top menu select Policies >> New >> New Policy.

Enter a Name for the new policy; In Inherit from, select “None”.

Click “Next” and Select “Yes”.

Choose the applicable computers that will inherit this policy, and click “Next”.

Ensure all options are selected from the “Select which Computer properties to base new Policy on:” window, and click “Next”.

Click “Finish”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66551r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65903'
  tag rid: 'SV-80393r1_rule'
  tag stig_id: 'TMDS-00-000130'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-71979r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
