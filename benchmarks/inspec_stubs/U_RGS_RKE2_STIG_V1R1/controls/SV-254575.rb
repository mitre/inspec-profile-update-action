control 'SV-254575' do
  title 'Rancher RKE2 registry must contain the latest images with most recent updates and execute within Rancher RKE2 runtime as authorized by IAVM, CTOs, DTMs, and STIGs.'
  desc 'Software supporting RKE2, images in the registry must stay up to date with the latest patches, service packs, and hot fixes. Not updating RKE2 and container images will expose the organization to vulnerabilities.

Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously.

Organization-defined time periods for updating security-relevant container platform components may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw).

This requirement will apply to software patch management solutions used to install patches across the enclave and to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

RKE2 components will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. RKE2 registry will ensure the images are current. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Authenticate on the RKE2 Control Plane. 
Run command:
kubectl version --short

If kubectl version has a setting not supporting Kubernetes skew policy, this is a finding.

Note: Kubernetes Skew Policy can be found at: https://kubernetes.io/docs/setup/release/version-skew-policy/#supported-versions.'
  desc 'fix', 'Upgrade RKE2 to the supported version. Institute and adhere to the policies and procedures to ensure that patches are consistently applied within the time allowed.'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58059r859293_chk'
  tag severity: 'medium'
  tag gid: 'V-254575'
  tag rid: 'SV-254575r859295_rule'
  tag stig_id: 'CNTR-R2-001620'
  tag gtitle: 'SRG-APP-000456-CTR-001125'
  tag fix_id: 'F-58008r859294_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
