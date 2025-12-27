control 'SV-18881' do
  title 'All VTC system management systems/servers are not configured in compliance with all applicable STIGs'
  desc 'Most VTC system vendors offer a range of centralized VTC system management applications and application suites. These include VTC endpoint and MCU managers, gatekeeper, gateway, and scheduling software. Gateways, gatekeepers, and scheduling systems are discussed later in this document.
     
The advantage of implementing a management system for the management of VTC endpoints is that all endpoints can be managed from a central location and their configuration can be standardized. This is a good thing in that configuration changes made on any given endpoint for temporary purposes can be discovered and corrected easily. 
     
The disadvantage is that their use makes all managed VTC endpoints vulnerable and at risk of compromise if the management system is compromised. 
     
While compliance with all applicable STIGs is covered in the next subsection, additional guidance may be provided in a future release of this or a related document.
     
Typically, VTC vendors provide their management applications and other infrastructure products on appliances with embedded operating systems (modified/scaled down, general purpose, or proprietary) and other application and database code (proprietary or otherwise). Some of these applications may be provided to run on a general purpose platform. 
     
In general, to mitigate risks, all VTC system management applications and application suites, including endpoint and MCU managers, gateways, gatekeepers, and scheduling systems must be operated on secure or hardened platforms and comply with all applicable DoD STIGs with specific emphasis on user accounts, roles/permissions, access control, and auditing.'
  desc 'check', '[IP]; Interview the IAO and validate compliance with the following requirement:
     
Ensure all VTC system management suites/applications, gateways, and scheduling systems are configured in compliance with all applicable STIGs and are operated on STIG compliant platforms.
     
Note:   The following is a listing of, but possibly not all, applicable STIGs:
     
- Operating system e.g., Windows, UNIX
- Web Server, Application Services 
- Database
- Application Development, Application Security Checklist
     
Determine the STIGs that are applicable to the site’s VTC system management suites/applications, gateways, and scheduling systems. Inspect documentation regarding the IA review of these systems and applications against the applicable STIGs. This is a finding only if the site’s VTC system management suites/applications, gateways, and scheduling systems have not been reviewed against all applicable STIGs. This is not a finding if all applicable reviews have been performed regardless of the number of findings determined during those reviews. The IA posture of the reviewed system is based on the results of those reviews.'
  desc 'fix', '[IP]; Perform the following tasks:
- Determine the STIGs that are applicable to the VTC system’s management suites/applications, gateways, and scheduling systems.
- Configure these systems in accordance with the requirements in the applicable STIGs'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18977r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17707'
  tag rid: 'SV-18881r1_rule'
  tag stig_id: 'RTS-VTC 3460.00'
  tag gtitle: 'RTS-VTC 3460.00 [IP]'
  tag fix_id: 'F-17604r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Not using DoD STIG guidance to secure VTC system/device management systems/servers could lead to denial of service or the disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
