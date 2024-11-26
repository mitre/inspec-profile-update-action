control 'SV-239121' do
  title 'The Photon operating system audit files and directories must have correct permissions.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operations on audit information.'
  desc 'check', 'At the command line, execute the following command:

# stat -c "%n is owned by %U and group owned by %G" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace

If any file is not owned by root and group owned by root, this is a finding.'
  desc 'fix', 'At the command line, execute the following command for each file returned:

# chown root:root <file>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42332r675169_chk'
  tag severity: 'medium'
  tag gid: 'V-239121'
  tag rid: 'SV-239121r675171_rule'
  tag stig_id: 'PHTN-67-000050'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-42291r675170_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
