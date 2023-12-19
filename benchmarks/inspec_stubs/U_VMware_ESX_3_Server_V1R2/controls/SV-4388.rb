control 'SV-4388' do
  title 'The anonymous FTP account must be configured to use chroot or a similarly isolated environment.'
  desc 'If an anonymous FTP account does not use a chroot or similarly isolated environment,  the system may be more vulnerable to exploits against the FTP service.  Such exploits could allow an attacker to gain shell access to the system and view, edit, or remove sensitive files.'
  desc 'check', 'Consult vendor documentation for the anonymous FTP service to determine the necessary configuration for operating the service in a chroot environment. If the system is not configured to operate the anonymous FTP service in a chroot environment, this is a finding.'
  desc 'fix', 'Configure the anonymous FTP service to operate in a chroot environment.  Consult vendor documentation for the necessary configuration procedures.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8270r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4388'
  tag rid: 'SV-4388r2_rule'
  tag stig_id: 'GEN005020'
  tag gtitle: 'GEN005020'
  tag fix_id: 'F-4299r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
