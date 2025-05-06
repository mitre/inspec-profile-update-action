control 'SV-51295' do
  title 'Development systems must have antivirus installed and enabled with up-to-date signatures.'
  desc 'Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing the most current virus scan program provides the ability to detect this malicious code before extensive damage occurs.  Updated virus scan data files help protect a system, as new malware is identified by the software vendors on a regular basis.'
  desc 'check', "Review development images to determine whether antivirus is installed and configured with current signatures.   If antivirus is missing on development systems, this is a finding.  

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Install antivirus with current signatures on development systems.'
  impact 0.7
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46712r3_chk'
  tag severity: 'high'
  tag gid: 'V-39437'
  tag rid: 'SV-51295r1_rule'
  tag stig_id: 'ENTD0070'
  tag gtitle: 'ENTD0070 - Antivirus not installed on development systems.'
  tag fix_id: 'F-44450r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1, ECVP-1'
end
