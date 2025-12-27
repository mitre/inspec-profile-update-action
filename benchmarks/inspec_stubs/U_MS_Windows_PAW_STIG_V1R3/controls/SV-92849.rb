control 'SV-92849' do
  title 'Site IT resources designated as high value by the Authorizing Official (AO) must be remotely managed only via a Windows privileged access workstation (PAW).'
  desc 'The AO must designate which IT resources are high value. The list must include the following IT resources:

- Directory service (including Active Directory)
- Cloud service
- Identity management service
- Privileged access management service
- Credential management service
- Security management service (anti-virus, network monitoring/scanning, IDS/IPS, etc.)
- Any sensitive business/mission service
- Any other IT resource designated as high value by the AO

Note: A high-value IT resource is defined as any IT resource whose purpose is considered critical to the organization or whose loss or compromise would cause a significant impact on the organization.

Note: Sensitive business/mission service is any business or mission service that needs additional protection from higher-risk IT services based on the nature of the function it provides; sensitivity of the data it consumes, processes, or stores; or criticality to the operation of the organization.

High-value IT resources are the most important and critical IT resources within an organization. They contain the most sensitive data in an organization, perform the most critical tasks of an organization, or have access to and can control all or nearly all IT resources within an organization. Administrator accounts for high-value IT resources must be protected against various threats and attacks because threats to sensitive privileged accounts are high and risk of compromise is increasing. Requiring a PAW used exclusively for remote administrative management of designated high-value IT resources, including servers, workstations, directory services, applications, databases, and network components, will provide a separate "channel" for the performance of administrative tasks on high-value IT resources and isolate these functions from the majority of threats and attack vectors found on higher-risk standard client systems.

Some IT resources, by the nature of the function they perform, should always be considered high value and should be remotely administered only via a PAW. The IT resources listed above are in this category.

Note: The term "manage" in the Requirement statement includes any remote connection to a high-value IT resource (for example, to view resource status and current configuration or to make changes to any resource configuration).'
  desc 'check', 'Review site documentation to confirm required high-value IT resources are remotely managed only via a PAW.

Verify the site maintains a list of designated high-value IT resources and the list contains the following IT resources (if deployed at the site):

- Active Directory
- Cloud service
- Identity management service
- Privileged access management service
- Credential management service
- Security management service (anti-virus, network monitoring/scanning, IDS/IPS, etc.)
- Any sensitive business/mission service
- Any other IT resource designated as high value by the Authorizing Official (AO)

Identify the PAWs set up to manage these high-value IT resources.

If the organization does not maintain a list of designated high-value IT resources or has not set up PAWs to remotely manage its high-value IT resources, this is a finding.'
  desc 'fix', "The Information System Security Manager (ISSM) or other site personnel will assist the Authorizing Official (AO) in designating and documenting which IT resources in the organization are high value. The organization's list of high-value IT resources will include the following:

- Active Directory
- Cloud service
- Identity management service
- Privileged access management service
- Credential management service
- Security management service (anti-virus, network monitoring/scanning, IDS/IPS, etc.)
- Any sensitive business service
- Any other IT resource designated as high value by the AO

Set up procedures to ensure a Windows PAW is used to remotely manage each of these types of IT resources."
  impact 0.5
  ref 'DPMS Target Privileged Access Workstation (Windows)'
  tag check_id: 'C-77709r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78143'
  tag rid: 'SV-92849r1_rule'
  tag stig_id: 'WPAW-00-000200'
  tag gtitle: 'PAW-00-000200'
  tag fix_id: 'F-84865r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
