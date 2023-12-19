control 'SV-221706' do
  title 'The Oracle Linux operating system must have a host-based intrusion detection tool installed.'
  desc "Adding host-based intrusion detection tools can provide the capability to take actions automatically in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime.

"
  desc 'check', 'Consult with the SA or ISSO to determine if a host-based intrusion detection application is loaded on the system. Per OPORD 16-0080, the preferred intrusion detection system is McAfee HBSS available through the U.S. Cyber Command (USCYBERCOM).

If another host-based intrusion detection application is in use, such as SELinux, this must be documented and approved by the local Authorizing Official.

Procedure:
Examine the system to determine if the Host Intrusion Prevention System (HIPS) is installed:

# rpm -qa | grep MFEhiplsm

Verify the McAfee HIPS module is active on the system:

# ps -ef | grep -i "hipclient" 

If the MFEhiplsm package is not installed, check for another intrusion detection system:

# find / -name <daemon name>

Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system.

Determine if the application is active on the system:

# ps -ef | grep -i <daemon name>

If the MFEhiplsm package is not installed and an alternate host-based intrusion detection application has not been documented for use, this is a finding.

If no host-based intrusion detection system is installed and running on the system, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee HIPS package, available from USCYBERCOM.

Note: If the system does not support the McAfee HIPS package, install and enable a supported intrusion detection system application and document its use with the Authorizing Official.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23421r419190_chk'
  tag severity: 'medium'
  tag gid: 'V-221706'
  tag rid: 'SV-221706r603260_rule'
  tag stig_id: 'OL07-00-020019'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-23410r419191_fix'
  tag satisfies: ['SRG-OS-000191-GPOS-00080', 'SRG-OS-000196']
  tag 'documentable'
  tag legacy: ['SV-108255', 'V-99151']
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
