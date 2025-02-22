control 'SV-214214' do
  title 'The Infoblox NIOS version must be at the appropriate version.'
  desc 'Infoblox NIOS is updated on a regular basis to add feature support, implement bug fixes, and address security vulnerabilities. NIOS is a hardened system with no direct user access to the software components. The review of security vulnerabilities such as MITRE Common Vulnerabilities and Exposure (CVE) can be accomplished by review of the running system NIOS version and published security information. Review of specific or individual software component versions within NIOS is not sufficient validation, as Infoblox modifies these software components and may or may not be subject to vulnerabilities that exist in unmodified publicly available source code.

Infoblox may support multiple versions of NIOS, each of which may address the same security vulnerability at different patch releases. It is not necessary for an Infoblox customer to run the highest possible version, rather they should run the supported version applicable to their environment and ensure it is patched to address all known vulnerabilities.

Infoblox publishes security information within each NIOS version release notes and on the Infoblox Support Knowledge Base. Infoblox customers can also use the support portal to validate security questions and applicability of vulnerabilities.'
  desc 'check', 'Infoblox systems utilize a modified version of BIND DNS software which adds features as well as addresses security issues outside of those provided by ISC. Infoblox systems are provided as a hardened appliance, and do not allow user access or upgrading of software components including BIND. The Infoblox support portal is the authoritative source to validate version and applicability of vulnerabilities.

Verify the NIOS version by review of "Grid, Upgrade" tab to show all members are at the current version.
Utilize the Infoblox support knowledgebase to obtain current version information.

If Infoblox NIOS is not at the current approved version level, this is a finding.'
  desc 'fix', 'Log on to the support site and download the current version of NIOS and perform a Grid upgrade.

Refer to the Infoblox NIOS Administration Guide if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15429r295905_chk'
  tag severity: 'medium'
  tag gid: 'V-214214'
  tag rid: 'SV-214214r612370_rule'
  tag stig_id: 'IDNS-7X-000860'
  tag gtitle: 'SRG-APP-000516-DNS-000103'
  tag fix_id: 'F-15427r295906_fix'
  tag 'documentable'
  tag legacy: ['SV-83133', 'V-68643']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
