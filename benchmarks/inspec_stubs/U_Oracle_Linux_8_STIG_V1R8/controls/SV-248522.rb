control 'SV-248522' do
  title 'The OL 8 operating system must implement the Endpoint Security for Linux Threat Prevention tool.'
  desc "Adding endpoint security tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of the system, which may not otherwise exist in an organization's systems management regime."
  desc 'check', 'Per OPORD 16-0080, the preferred endpoint security tool is McAfee Endpoint Security for Linux (ENSL) in conjunction with SELinux. 

Check that the following package has been installed:

# rpm -qa | grep -i mcafeetp

If the "mcafeetp" package is not installed, this is a finding.

Verify that the daemon is running:

# ps -ef | grep -i mfetpd

If the daemon is not running, this is a finding.'
  desc 'fix', 'Install and enable the latest McAfee ENSLTP package.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51956r779130_chk'
  tag severity: 'medium'
  tag gid: 'V-248522'
  tag rid: 'SV-248522r779132_rule'
  tag stig_id: 'OL08-00-010001'
  tag gtitle: 'SRG-OS-000191-GPOS-00080'
  tag fix_id: 'F-51910r779131_fix'
  tag 'documentable'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)']
end
