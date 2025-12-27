control 'SV-219544' do
  title 'The system package management tool must cryptographically verify the authenticity of system software packages during installation.'
  desc "Ensuring the validity of packages' cryptographic signatures prior to installation ensures the provenance of the software and protects against malicious tampering."
  desc 'check', 'To determine whether "yum" is configured to use "gpgcheck", inspect "/etc/yum.conf" and ensure the following appears in the "[main]" section: 

gpgcheck=1

A value of "1" indicates that "gpgcheck" is enabled. Absence of a "gpgcheck" line or a setting of "0" indicates that it is disabled.  If GPG checking is not enabled, this is a finding.

If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.'
  desc 'fix', %q(The "gpgcheck" option should be used to ensure checking of an RPM package's signature always occurs prior to its installation. To configure yum to check package signatures before installing them, ensure the following line appears in "/etc/yum.conf" in the "[main]" section: 

gpgcheck=1)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21269r358172_chk'
  tag severity: 'medium'
  tag gid: 'V-219544'
  tag rid: 'SV-219544r793801_rule'
  tag stig_id: 'OL6-00-000013'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-21268r358173_fix'
  tag 'documentable'
  tag legacy: ['V-50701', 'SV-64907']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
