control 'SV-240962' do
  title 'The vAMI must log all login events.'
  desc "Being able to work on a system through multiple views into the application allows a user to work more efficiently and more accurately. Before environments with windowing capabilities or multiple desktops, a user would log onto the application from different workstations or terminals. With today's workstations, this is no longer necessary and may signal a compromised session or user account. When concurrent logons are made from different workstations to the management interface, a log record needs to be generated. This allows the system administrator to investigate the incident and to be aware of the incident."
  desc 'check', %q(At the command prompt, execute the following command:

grep -E 'auth.*unix' /etc/pam.d/vami-sfcb

If no line is returned or the returned line does contain the option "debug", this is a finding.)
  desc 'fix', 'Navigate to and open /etc/pam.d/vami-sfcb.

Configure the vami-sfcb file with the following value: "auth required /lib64/security/pam_unix.so debug"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44195r676051_chk'
  tag severity: 'medium'
  tag gid: 'V-240962'
  tag rid: 'SV-240962r879877_rule'
  tag stig_id: 'VRAU-VA-000625'
  tag gtitle: 'SRG-APP-000506-AS-000231'
  tag fix_id: 'F-44154r676052_fix'
  tag 'documentable'
  tag legacy: ['SV-100919', 'V-90269']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
