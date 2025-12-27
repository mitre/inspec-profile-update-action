control 'SV-100281' do
  title 'The xinetd.d directory must have mode 0755 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause denial of service or increase the attack surface of the system.'
  desc 'check', 'Check the permissions of the "xinetd" configuration directories:

# ls -dlL /etc/xinetd.d

If the mode of the directory is more permissive than "0755", this is a finding.'
  desc 'fix', 'Change the mode of the directory:

# chmod 0755 /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89323r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89631'
  tag rid: 'SV-100281r1_rule'
  tag stig_id: 'VRAU-SL-000530'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-96373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
