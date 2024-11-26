control 'SV-222654' do
  title 'The designer must create and update the Design Document for each release of the application.'
  desc 'This requirement is meant to apply to developers or organizations that are doing application development work.

The application design document or configuration guide includes configuration settings, recommendations and best practices that pertain to the secure deployment of the application.

It also contains the detailed functional architecture as well as any changes to the application architecture corresponding to a new version release and must be documented to ensure all risks are assessed and mitigated to the maximum extent practical.

Failure to do so may result in unexposed risk, and failure to mitigate the risk leading to failure or compromise of the system.'
  desc 'check', 'This requirement is meant to apply to developers or organizations that are doing application development work. If the organization operating the application is not doing the development or managing the development of the application, the requirement is not applicable.

Ask the application representative for the design document for the application. Review the design document.

Examine the design document and/or the threat model for the application and verify the following information is documented:

- All external interfaces.
- The nature of information being exchanged
- Any protections on the external interface
- User roles required for access control and the access privileges assigned to each role
- Unique security requirements (e.g., encryption of key data elements at rest)
- Categories of sensitive information processed by the application and their specific protection plans (e.g., PII, HIPAA).
- Restoration priority of subsystems, processes, or information
- Verify the organization includes documentation describing the design and implementation details of the security controls employed within the information system with sufficient detail
- Application incident response plan that provides details on how to provide the development team with application vulnerability or bug information.

If the design document is incomplete, this is a finding.'
  desc 'fix', 'Create and maintain the Design Document for each release of the application and identify the following:

- All external interfaces (from the threat model)
- The nature of information being exchanged
- Categories of sensitive information processed or stored and their specific protection plans
- The protection mechanisms associated with each interface
- User roles required for access control
- Access privileges assigned to each role
- Unique application security requirements
- Categories of sensitive information processed or stored and specific protection plans (e.g., Privacy Act, HIPAA, etc.)
- Restoration priority of subsystems, processes, or information.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24324r561282_chk'
  tag severity: 'low'
  tag gid: 'V-222654'
  tag rid: 'SV-222654r561284_rule'
  tag stig_id: 'APSC-DV-003220'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24313r561283_fix'
  tag 'documentable'
  tag legacy: ['SV-85009', 'V-70387']
  tag cci: ['CCI-000366', 'CCI-003233']
  tag nist: ['CM-6 b', 'SA-15 a']
end
