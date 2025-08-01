control 'SV-37746' do
  title 'The system must have a host-based intrusion detection tool installed.'
  desc "Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Ask the SA or ISSO if a host-based intrusion detection application is loaded on the system. Per OPORD 16-0080 the preferred intrusion detection system is McAfee HBSS available through Cybercom.

If another host-based intrusion detection application is in use, such as SELinux, this must be documented and approved by the local Authorizing Official

Procedure:
Examine the system to see if the Host Intrusion Prevention System (HIPS) is installed

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
  desc 'fix', 'Install and enable the latest McAfee HIPS package, available from Cybercom.

If the system does not support the McAfee HIPS package, install and enable a supported intrusion detection system application and document its use with the Authorizing Official.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36942r3_chk'
  tag severity: 'medium'
  tag gid: 'V-782'
  tag rid: 'SV-37746r3_rule'
  tag stig_id: 'GEN006480'
  tag gtitle: 'GEN006480'
  tag fix_id: 'F-32207r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001259']
  tag nist: ['SI-4 (1)']
end
