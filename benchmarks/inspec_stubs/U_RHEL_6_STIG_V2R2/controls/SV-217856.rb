control 'SV-217856' do
  title 'The system package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc "Ensuring all packages' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering."
  desc 'check', 'To determine whether "yum" has been configured to disable "gpgcheck" for any repos, inspect all files in "/etc/yum.repos.d" and ensure the following does not appear in any sections: 

gpgcheck=0

A value of "0" indicates that "gpgcheck" has been disabled for that repo. 
If GPG checking is disabled, this is a finding.

If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.'
  desc 'fix', 'To ensure signature checking is not disabled for any repos, remove any lines from files in "/etc/yum.repos.d" of the form: 

gpgcheck=0'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19337r376583_chk'
  tag severity: 'low'
  tag gid: 'V-217856'
  tag rid: 'SV-217856r603264_rule'
  tag stig_id: 'RHEL-06-000015'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-19335r376584_fix'
  tag 'documentable'
  tag legacy: ['V-38487', 'SV-50288']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
