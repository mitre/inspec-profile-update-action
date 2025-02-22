control 'SV-18715' do
  title 'The VTC endpoints and system components must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the network device to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the network device. Security-related parameters are those parameters impacting the security state of the network device, including the parameters required to satisfy other security control requirements.

Traditionally, VTC systems and devices do not support DoD requirements on all access points and features. However, DoD VTC systems are subject to these policies that provide access controls, address vulnerabilities, and provide for user and administrator accountability. This requirement highlights the lack of IA support in security readiness review as well as in certification and accreditation reports. The remaining requirements attempt to define mitigations to this lack of policy compliance to the greatest extent possible.'
  desc 'check', 'Review the VTC system architecture and ensure the VTC endpoints and system components are configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs. Ensure all VTC endpoints and system components comply with the following NIST 800-53 (Rev. 4) IA controls:
- Account Management (AC-2)
- Individual ID & Password (IA-5)
- Lockout on logon failure (AC-7)
- Warning Banner (AC-8)
- Roles (privileged access) (AC-1)
- Least Privilege (AC-6, SA-17)
- Security audit (AU-2)
- Audit Content (AU-3)
- Audit Trail Protection (AU-12)

If the VTC endpoints and system components are not configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, this is a finding.'
  desc 'fix', 'Procure and implement VTC endpoints and system components configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs. Encourage vendors to develop VTC systems and devices that provide robust IA features that support compliance with DoD policies for all devices.'
  impact 0.3
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18889r2_chk'
  tag severity: 'low'
  tag gid: 'V-17589'
  tag rid: 'SV-18715r2_rule'
  tag stig_id: 'RTS-VTC 1000.00'
  tag gtitle: 'RTS-VTC 1000'
  tag fix_id: 'F-17507r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Designated Approving Authority']
  tag ia_controls: 'DCBP-1, ECSC-1'
end
