control 'SV-228840' do
  title 'The Palo Alto Networks security platform must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

The DoD continually assesses the ports, protocols, and services that can be used for network communications. Some ports, protocols, or services have known exploits or security weaknesses. Network traffic using these ports, protocols, and services must be prohibited or restricted in accordance with DoD policy. It is the responsibility of the enclave owner to have the applications the enclave uses registered in the PPSM database.

The Palo Alto Networks security platform must be configured to prevent or restrict the use of prohibited ports, protocols, and services throughout the network by filtering the network traffic and disallowing or redirecting traffic as necessary.  If the device is in a Deny-by-Default posture and what is allowed through the filter is IAW DoD Instruction 8551, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to PPS being blocked are satisfied. 

Since the enclave or system may support custom applications, it may be necessary to configure a Custom Application.  This requires detailed analysis of the application traffic and requires validation testing before deployment.'
  desc 'check', 'Review the list of authorized applications, endpoints, services, and protocols that has been added to the PPSM database.
Go to Policies >> Security
Review each of the configured security policies in turn.
If any of the policies allows traffic that is prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', 'To configure a security policy:
Go to Policies >> Security
Select "Add".
In the "Security Policy Rule" window, complete the required fields.
In the "General" tab, complete the "Name" and "Description" fields.
In the "Source" tab, complete the "Source Zone" and "Source Address" fields.  
In the "User" tab, select "Any" or complete the "Source User" field; this is completed if the policy performs the defined actions based on an individual user or group of users.  If using GlobalProtect with Host Information Profile (HIP) enabled, select the "HIP Profiles" check box, and add the HIP Object or HIP Profile.
In the "Destination" tab, complete the "Destination Zone" and "Destination Address" fields. 
In the "Applications" tab, select the authorized applications.
In the "Service/URL Category" tab, select application-default. To add a service, select the "Service" check box, select "Add", and select a listed service or add a new service or service group.
In the "Actions" tab, select either "Deny" or "Allow" (as required) as the resulting action.  Select the required Log Setting and Profile Settings as necessary.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31075r513815_chk'
  tag severity: 'medium'
  tag gid: 'V-228840'
  tag rid: 'SV-228840r557387_rule'
  tag stig_id: 'PANW-AG-000038'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-31052r513816_fix'
  tag 'documentable'
  tag legacy: ['V-62563', 'SV-77053']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
