control 'SV-239120' do
  title 'The Photon operating system audit files and directories must have correct permissions.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operations on audit information.'
  desc 'check', 'At the command line, execute the following command:

# stat -c "%n is owned by %U and group owned by %G" /etc/audit/auditd.conf

If auditd.conf is not owned by root and group owned by root, this is a finding.'
  desc 'fix', 'At the command line, execute the following command:

# chown root:root /etc/audit/auditd.conf'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42331r675166_chk'
  tag severity: 'medium'
  tag gid: 'V-239120'
  tag rid: 'SV-239120r675168_rule'
  tag stig_id: 'PHTN-67-000049'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-42290r675167_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
