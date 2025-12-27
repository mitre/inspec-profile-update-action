control 'SV-239592' do
  title 'The SLES for vRealize must control remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

SLES for vRealize functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Check the SSH daemon configuration for listening network addresses:

# grep -i Listen /etc/ssh/sshd_config | grep -v '^#'

If no configuration is returned, or if a returned "Listen" configuration contains addresses not designated for management traffic, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration with the following command:

# sed -i "/^[^#]ListenAddress/ c\\ListenAddress = 0.0.0.0" /etc/ssh/sshd_config

Replace "0.0.0.0" with the listening network addresses designated for management traffic.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42825r662225_chk'
  tag severity: 'medium'
  tag gid: 'V-239592'
  tag rid: 'SV-239592r662227_rule'
  tag stig_id: 'VROM-SL-000950'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-42784r662226_fix'
  tag 'documentable'
  tag legacy: ['SV-99305', 'V-88655']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
