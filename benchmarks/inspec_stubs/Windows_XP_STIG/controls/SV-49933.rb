control 'SV-49933' do
  title 'Windows operating systems that are no longer supported by the vendor for security updates must not be installed on a system.'
  desc 'Windows operating systems that are no longer supported by Microsoft for security updates are not evaluated or updated for vulnerabilities leaving them open to potential attack.  Organizations must transition to a supported operating system to ensure continued support.'
  desc 'fix', 'Upgrade Windows XP systems to a supported operating system.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag severity: 'high'
  tag gid: 'V-4107'
  tag rid: 'SV-49933r2_rule'
  tag stig_id: 'WIN00-000001'
  tag gtitle: 'Unsupported Windows OS'
  tag fix_id: 'F-49198r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCSQ-1'
end
