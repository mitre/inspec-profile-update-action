control 'SV-7029' do
  title 'MFDs must not allow scan to SMTP (email).'
  desc 'The SMTP engines found on the MFDs reviewed when writing the MFD STIG did not have robust enough security features supporting scan to email. Because of the lack of robust security, scan to email will be disabled on MFD devices. Failure to disable this feature could lead to an untraceable and possibly undetectable compromise of sensitive data.

The SA will ensure MFDs do not allow scan to SMTP.'
  desc 'check', 'The reviewer will, with the assistance from the SA, verify devices do not allow scan to SMTP. If scan to SMTP is enabled on the MFD, this is a finding.

Note: With AO approval, strict usage policies, and user training, MFD scan to SMTP (email) is allowed if CAC/PKI authentication is implemented on the MFD. There must be a method implemented for non-repudiation and authenticated access. A USB/flash drive/thumb drive or any removable storage capability will not be installed.'
  desc 'fix', 'Disable the scan to SMTP (email) feature on all MFDs.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3019r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6804'
  tag rid: 'SV-7029r2_rule'
  tag stig_id: 'MFD07.005'
  tag gtitle: 'MFD scan to SMTP (email)'
  tag fix_id: 'F-6478r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
