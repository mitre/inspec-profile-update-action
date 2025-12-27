control 'SV-233309' do
  title 'Forescout must enforce approved access by employing admissions assessment filters that include, at a minimum, device attributes such as type, IP address, resource group, and/or mission conditions as defined in Forescout System Security Plan (SSP).  This is required for compliance with C2C Step 4.'
  desc "Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Many NACs include the ability to create network access control policies that include identity-based policies, role-based policies, and attribute-based policies. 

It is recommended that Forescout have the capability to expose collected data on the assessed endpoints through an API that can be accessed externally, or the NAC solution must supply an SDK to allow customers to export data. 

Admissions assessment filters should include, at a minimum, device attributes such as type, IP address, resource group, and/or mission conditions as defined in the Forescout SSP. Forescout should also track the following to facilitate security investigations: when each device was last admitted/readmitted to the network; owning organization; owning organization's organizational unit; geographic location or the nearest network switch; motherboard serial number and BIOS; globally unique ID; and which unique network access compliance policies each device passed or failed during the latest network admission/readmission.

The client may be denied admission based on a returned posture token. In most Forescout implementations, additional network access authorization policies can also be tied to the user's identity, but these features are out of scope for this STIG."
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Use the Forescout Administrator UI to ensure that the endpoint compliance assessment policies have been implemented per the SSP and are functioning correctly. 

If Forescout does not have compliance assessment policies configured this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure the endpoint compliance assessment policies per the SSP. Example only:

1. Log on to Forescout UI.
2. From the Policy tab, select the top most policy.
3. Select Add >> Classification >> Primary Classification, and then click "Next".
4. Give the policy a name, then click "Next".
5. If applicable, select the IP Address Range the policy will apply to, click "Ok", and then click "Next". 
6. Select "Finish, then click "Apply".'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36504r811366_chk'
  tag severity: 'high'
  tag gid: 'V-233309'
  tag rid: 'SV-233309r811367_rule'
  tag stig_id: 'FORE-NC-000010'
  tag gtitle: 'SRG-NET-000015-NAC-000020'
  tag fix_id: 'F-36469r803447_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
