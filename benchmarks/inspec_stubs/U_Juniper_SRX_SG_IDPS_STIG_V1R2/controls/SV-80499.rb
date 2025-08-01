control 'SV-80499' do
  title 'The Juniper Networks SRX Series Gateway IDPS must install updates for predefined signature objects, applications signatures, IDPS policy templates, and device software when new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Failing to update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. 

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be updated, including application software files, anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

Updates must be installed in accordance with the CCB procedures for the local organization. However, at a minimum: 

1. Updates designated as critical security updates by the vendor must be installed immediately.

2. Updates for predefined signature objects, applications signatures, IDPS policy templates, and device software must be installed immediately.

3. Updates for application software are installed in accordance with the CCB procedures.

4. Prior to automatically installing updates, either manual or automated integrity and authentication checking is required, at a minimum, for application software updates.'
  desc 'check', 'To check the version of the security package installed, enter the following command from the root on the device:

show security idp security-package-version

Compare the installed release with the latest available and approved release.

If a new release is available and not installed, this is a finding.'
  desc 'fix', "Since DoD does not allow the management port of security devices to be connected directly to the Internet, the required security package must be uploaded using the Juniper SRX offline process.

Directions are available in the document “How to perform offline IDP and Application signature database update in SRX” on the Juniper Networks support site. DoD network policy requires a local file repository be used to automate the update for network devices.

Before uploading updates, the IDP administrator must verify the updates are approved by the site's CCB procedures and are authorized for installation. Once all files have been downloaded and approved, install the security package on SRX from root.

Request security idp security-package install source-path /var/db/idpd/sec-download"
  impact 0.7
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-66657r1_chk'
  tag severity: 'high'
  tag gid: 'V-66009'
  tag rid: 'SV-80499r1_rule'
  tag stig_id: 'JUSX-IP-000010'
  tag gtitle: 'SRG-NET-000246-IDPS-00205'
  tag fix_id: 'F-72085r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
