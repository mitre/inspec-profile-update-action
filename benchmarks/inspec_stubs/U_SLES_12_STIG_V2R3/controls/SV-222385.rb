control 'SV-222385' do
  title 'The SUSE operating system must have a host-based intrusion detection tool installed.'
  desc "Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Ask the SA or ISSO if a host-based intrusion detection application is loaded on the system. Per OPORD 16-0080, the preferred intrusion detection system is McAfee HBSS available through the U.S. Cyber Command (USCYBERCOM).

If another host-based intrusion detection application is in use, such as AppArmor, this must be documented and approved by the local Authorizing Official.

Procedure:
Examine the system to see if the Host Intrusion Prevention System (HIPS) is installed:

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
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18385r369627_chk'
  tag severity: 'medium'
  tag gid: 'V-222385'
  tag rid: 'SV-222385r603262_rule'
  tag stig_id: 'SLES-12-010599'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-36322r602678_fix'
  tag 'documentable'
  tag legacy: ['V-92249', 'SV-102351']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
