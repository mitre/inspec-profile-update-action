control 'SRG-OS-000104-CLD-000160_rule' do
  title 'The CSO must be configured to use DOD PKI to uniquely identify and authenticate organizational users (or processes acting on behalf of
organizational users).'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Identity Federation requirements to enable CAC authentication of non-privileged DOD users to cloud hosted DOD (e.g., IaaS and PaaS) or SaaS provided systems and services is the responsibility of the cloud service offering, procuring DOD Component or Program Office. Mission Owners may choose to use the CSP's CAC services (based on Level), use a DOD federated offering, or install a virtual Directory Service.

For Impact Levels 2-5, the CSPs must have either a DOD PKI certificate or a DOD-approved External Certification Authority (ECA) medium-assurance PKI Certificate for each person that needs to communicate with DOD via encrypted email and for admin accounts. CSPs serving Level 6 systems will already have SIPRNet tokens / NSS PKI certificates for their system administrators by virtue of the connection to SIPRNet.

"
  desc 'check', 'Unless I&A is required by the information owner, for Impact Level 2 public cloud with non-privileged user access to publicly releasable information, this is not applicable.

Verify the CSO is configured to use DOD PKI to uniquely identify and authenticate organizational users (or processes acting on behalf of
organizational users) . 

If the CSO does not use DOD PKI to uniquely identify and authenticate organizational users (or processes acting on behalf of
organizational users), this is a finding.'
  desc 'fix', "Applies to Impact Level 4/5/6.
FedRAMP Moderate, High.

Mission Owners may choose to use the CSP's CAC services (based on level), use a DOD federated offering or install a virtual Directory Service."
  impact 0.5
  tag check_id: 'C-SRG-OS-000104-CLD-000160_chk'
  tag severity: 'medium'
  tag gid: 'SRG-OS-000104-CLD-000160'
  tag rid: 'SRG-OS-000104-CLD-000160_rule'
  tag stig_id: 'SRG-OS-000104-CLD-000160'
  tag gtitle: 'SRG-OS-000104-CLD-000160'
  tag fix_id: 'F-SRG-OS-000104-CLD-000160_fix'
  tag satisfies: ['SRG-OS-000104', 'SRG-OS-000377']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-001954']
  tag nist: ['IA-2', 'IA-2 (12)']
end
