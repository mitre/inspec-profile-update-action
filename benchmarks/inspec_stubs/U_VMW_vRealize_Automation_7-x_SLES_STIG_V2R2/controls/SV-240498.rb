control 'SV-240498' do
  title 'The SLES for vRealize must control remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Operating system functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Check the SSH daemon configuration for listening network addresses:

# grep -i Listen /etc/ssh/sshd_config | grep -v '^#'

If no configuration is returned, or if a returned "Listen" configuration contains addresses not designated for management traffic, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration /etc/ssh/sshd_config to specify listening network addresses designated for management traffic with the following command:

sed -i "/^ListenAddress/ c\\ListenAddress x.x.x.x" /etc/ssh/sshd_config

Note: Replace x.x.x.x with the desired remote access IP address.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43731r671233_chk'
  tag severity: 'medium'
  tag gid: 'V-240498'
  tag rid: 'SV-240498r852559_rule'
  tag stig_id: 'VRAU-SL-000975'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-43690r671234_fix'
  tag 'documentable'
  tag legacy: ['SV-100423', 'V-89773']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
