control 'SV-239104' do
  title 'The Photon operating system must only allow installation of packages signed by VMware.'
  desc 'Installation of any non-trusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by VMware.'
  desc 'check', 'At the command line, execute the following command:

# rpm -qa gpg-pubkey --qf "%{version}-%{release} %{summary}\\n"|grep -v "66fd4949-4803fe57"

If there is any output, an unsupported package has been installed and this is a finding.'
  desc 'fix', 'Confirm with VMware support that this package is not supported (for potential package additions after STIG publication). 

At the command line, execute the following command:

# rpm -e <package-name-from-check>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42315r675118_chk'
  tag severity: 'medium'
  tag gid: 'V-239104'
  tag rid: 'SV-239104r675120_rule'
  tag stig_id: 'PHTN-67-000032'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-42274r675119_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
