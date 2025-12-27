control 'SV-239135' do
  title 'The Photon operating system RPM package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc 'Installation of any non-trusted software, patches, service packs, device drivers, or operating system components can significantly affect the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.'
  desc 'check', 'At the command line, execute the following command:

# grep gpgcheck /etc/yum.repos.d/*

If "gpgcheck" is not set to "1" in any returned file, this is a finding.'
  desc 'fix', 'Open the file where gpgcheck is not set to "1" with a text editor. 

Remove any existing gpgcheck setting and add the following line at the end of the file:

gpgcheck=1'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42346r675211_chk'
  tag severity: 'medium'
  tag gid: 'V-239135'
  tag rid: 'SV-239135r856053_rule'
  tag stig_id: 'PHTN-67-000064'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-42305r675212_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
