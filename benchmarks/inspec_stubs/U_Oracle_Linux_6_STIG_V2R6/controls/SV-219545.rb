control 'SV-219545' do
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21270r358175_chk'
  tag severity: 'low'
  tag gid: 'V-219545'
  tag rid: 'SV-219545r793802_rule'
  tag stig_id: 'OL6-00-000015'
  tag gtitle: 'SRG-OS-000366'
  tag fix_id: 'F-21269r358176_fix'
  tag 'documentable'
  tag legacy: ['SV-64915', 'V-50709']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
