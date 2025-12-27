control 'SV-256898' do
  title 'Automation Controller must implement cryptography mechanisms to protect the integrity of information.'
  desc 'Encryption is critical for protection of remote access sessions. If encryption is not being used for integrity, malicious users may gain the ability to modify Automation Controller configuration. The use of cryptography for ensuring integrity of remote access sessions mitigates that risk.

Automation Controller utilizes a web management interface and scripted commands when allowing remote access. Web access requires the use of TLS and scripted access requires using SSH or some other form of approved cryptography. Automation Controller must have the ability to enable a secure remote admin capability.

FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

Automation Controller requires the use of Red Hat Enterprise Linux as an operating system and its underlying FIPS validated  cryptographic modules to ensure it meets FIPS 140-2 criteria.

'
  desc 'check', %q(As a System administrator for each Automation Controller host, check if the Operating System is FIPS enabled:

sysctl crypto.fips_enabled

If fips_enabled is not 1, this is a finding.

Verify the installed volume for Automation Controller is on a LUKS encrypted volume command:

AAPROOT='/var/lib/awx' && cryptsetup status `df -T ${AAPROOT} | cut -d ' ' -f 1 | tail -n 1 `  | grep type | grep -i luks || echo "FAILED"

If "FAILED" is displayed, this is a finding.

Verify this LUKS encrypted volume is using FIPS-compliant cryptographic functions command:

allowed_FIPS_ciphers=('aes.*\(256\|384\|512\\)') ; echo "${allowed_FIPS_ciphers[*]}"  | tr ' ' '\n' >tempfile && cryptsetup status `df -T ${AAPROOT} | cut -d ' ' -f 1 | tail -n 1 ` | grep -e '\(cipher\|keysize\\)' | awk '{print $2}' | paste -s -d '-' | grep -f tempfile 1>/dev/null || echo "FAILED" && rm -f tempfile

If the output is not 1, this is a finding.)
  desc 'fix', %q(As an administrator for each Automation Controller host, configure the Operating System to be FIPS enabled command:

sudo fips-mode-setup --enable

Reboot each system.

Configure Ansible Automation Platform installation location to reside on a LUKS encrypted volume:

Add a LUKS volume using default or other encrypted volume in accordance with organizationally defined policy. The '/var/lib/awx' filesystem must reside on this volume.

Reinstall the Ansible Automation Platform. 

Note: The phrasing "Reinstall the Ansible Automation Platform." is applicable here; the installer cannot just be rerun on the same system.

Reinstall the operating system on the Automation Controller server with FIPS mode enabled at install time by following the guidance located here:
https://access.redhat.com/solutions/5416081
OR 
Enable FIPS mode without reinstalling the operating system by following the guidance located here:
https://access.redhat.com/solutions/137833

If the operating system was reinstalled, reinstall Automation Controller by following the guidance located here:
https://docs.ansible.com/ansible-tower/latest/html/installandreference/index.html)
  impact 0.7
  ref 'DPMS Target Red Hat Ansible Automation Controller App Server'
  tag check_id: 'C-60573r903538_chk'
  tag severity: 'high'
  tag gid: 'V-256898'
  tag rid: 'SV-256898r903553_rule'
  tag stig_id: 'APAS-AT-000012'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-60515r903515_fix'
  tag satisfies: ['SRG-APP-000015-AS-000010', 'SRG-APP-000179-AS-000129', 'SRG-APP-000224-AS-000152', 'SRG-APP-000231-AS-000133', 'SRG-APP-000231-AS-000156', 'SRG-APP-000416-AS-000140', 'SRG-APP-000428-AS-000265', 'SRG-APP-000429-AS-000157', 'SRG-APP-000439-AS-000274', 'SRG-APP-000440-AS-000167', 'SRG-APP-000514-AS-000136']
  tag 'documentable'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-001199', 'CCI-001453', 'CCI-002418', 'CCI-002421', 'CCI-002450', 'CCI-002475', 'CCI-002476']
  tag nist: ['IA-7', 'SC-23 (3)', 'SC-28', 'AC-17 (2)', 'SC-8', 'SC-8 (1)', 'SC-13 b', 'SC-28 (1)', 'SC-28 (1)']
end
