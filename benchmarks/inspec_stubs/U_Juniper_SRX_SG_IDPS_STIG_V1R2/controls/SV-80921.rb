control 'SV-80921' do
  title 'The Juniper Networks SRX Series Gateway IDPS must automatically install updates to signature definitions.'
  desc "Failing to automatically update malicious code protection mechanisms, including application software files, signature definitions, and vendor-provided rules, leaves the system vulnerable to exploitation by recently developed attack methods and programs. An automatic update process ensures this important task is performed without the need for Security Control Auditor (SCA) intervention.

The IDPS is a key malicious code protection mechanism in the enclave infrastructure. To ensure this protection is responsive to changes in malicious code threats, IDPS components must be automatically updated, including anti-virus signatures, detection heuristics, vendor-provided rules, and vendor-provided signatures.

If a DoD patch management server or update repository having the tested/verified updates is available for the IDPS component, the components must be configured to automatically check this server/site for updates and install new updates. 

If a DoD server/site is not available, the component must be configured to automatically check a trusted vendor site for updates. A trusted vendor is either commonly used by DoD, specifically approved by DoD, the vendor from which the equipment was purchased, or approved by the local program's CCB."
  desc 'check', 'Verify automatic updates are configured.

[edit]
show security idp

If updates are not automatically installed, this is a finding.'
  desc 'fix', 'The following example configures automatic updates of the IDP signature database:

Specify the URL to use.

[edit]
set security idp security-package url <DoD repository>

Create a schedule for the automatic downloads.

set security idp security-package automatic interval <interval>
set security idp security-package automatic enable

Also, recommend a local log be created to track when automated updates are performed for troubleshooting purposes.

set system syslog file IDP_OPERATIONS any any match IDP_SCHEDULE'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66431'
  tag rid: 'SV-80921r1_rule'
  tag stig_id: 'JUSX-IP-000026'
  tag gtitle: 'SRG-NET-000251-IDPS-00178'
  tag fix_id: 'F-72507r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
