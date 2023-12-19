control 'SV-234801' do
  title 'The SUSE operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).'
  desc "Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Per OPORD 16-0080, the preferred intrusion detection system is McAfee Host Intrusion Prevention System (HIPS) in conjunction with SELinux. McAfee Endpoint Security for Linux (ENSL) is an approved alternative to McAfee Virus Scan Enterprise (VSE) and HIPS.

Procedure:
Verify the SUSE operating system deploys ENSLTP.

Check that the following package has been installed:

# rpm -qa | grep isectp

If the "isectp" package is not installed, this is a finding.

Verify that the daemon is running:

# ps -ef | grep -i “isectpd”

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-37989r618672_chk'
  tag severity: 'medium'
  tag gid: 'V-234801'
  tag rid: 'SV-234801r622137_rule'
  tag stig_id: 'SLES-15-010001'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-37952r618673_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
