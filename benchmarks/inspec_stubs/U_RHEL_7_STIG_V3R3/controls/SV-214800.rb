control 'SV-214800' do
  title 'The Red Hat Enterprise Linux operating system must have a host-based intrusion detection tool installed.'
  desc "Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Per OPORD 16-0080, the preferred intrusion detection system is McAfee Host Intrusion Prevention System (HIPS) in conjunction with SELinux. McAfee Endpoint Security for Linux (ENSL) is an approved alternative to McAfee Virus Scan Enterprise (VSE) and HIPS. For RHEL 7 systems, SELinux is an approved alternative to McAfee HIPS.

Procedure:
Examine the system to determine if the Host Intrusion Prevention System (HIPS) is installed:

# rpm -qa | grep MFEhiplsm

Verify that the McAfee HIPS module is active on the system:

# ps -ef | grep -i “hipclient”

If the MFEhiplsm package is not installed, check for another intrusion detection system:

# find / -name <daemon name>

Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system.

Determine if the application is active on the system:

# ps -ef | grep -i <daemon name>

If the MFEhiplsm package is not installed and an alternate host-based intrusion detection application has not been documented for use, this is a finding.

If no host-based intrusion detection system is installed and running on the system, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee HIPS package or McAfee ENSL.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-16000r462531_chk'
  tag severity: 'medium'
  tag gid: 'V-214800'
  tag rid: 'SV-214800r603261_rule'
  tag stig_id: 'RHEL-07-020019'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36317r602660_fix'
  tag 'documentable'
  tag legacy: ['V-92255', 'SV-102357']
  tag cci: ['CCI-001263']
  tag nist: ['SI-4 (5)']
end
