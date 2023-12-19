control 'SV-31547' do
  title 'Active Directory data must be backed up daily for systems with a Risk Management Framework categorization for Availability of moderate or high.  Systems with a categorization of low must be backed up weekly.'
  desc 'Failure to maintain a current backup of directory data could make it difficult or impossible to recover from incidents including hardware failure or malicious corruption.  A failure to recover from the loss of directory data used in identification and authentication services (i.e., Active Directory) could result in an extended loss of availability.'
  desc 'check', "Review the organization's procedures for the backing up active directory data.
Verify the frequency at which active directory data is backed up.
If the Availability categorization of the domain is low, this must be at least weekly.
If the Availability categorization of the domain is moderate or high, this must be at least daily.
Verify the type of backup is appropriate to capturing the directory data.  For AD domain controllers, this must include a System State data backup.

If any of these conditions are not met, this is a finding."
  desc 'fix', "Update the organization's procedures for the backing up active directory data.
Ensure the frequency at which active directory data is backed up is as follows:
If the Availability categorization of the domain is low, this must be at least weekly.
If the Availability categorization of the domain is moderate or high, this must be at least daily.
Ensure the type of backup is appropriate to capturing the directory data.  For AD domain controllers, this must include a System State data backup."
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-66403r2_chk'
  tag severity: 'medium'
  tag gid: 'V-25385'
  tag rid: 'SV-31547r3_rule'
  tag stig_id: 'DS00.0160_AD'
  tag gtitle: 'Directory Data Backup'
  tag fix_id: 'F-71791r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
