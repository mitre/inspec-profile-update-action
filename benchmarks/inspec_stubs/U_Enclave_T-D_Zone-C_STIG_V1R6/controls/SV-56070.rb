control 'SV-56070' do
  title 'The organization must create a policy and procedures document for proper handling and transport of data entering (physically or electronically) the test and development environment.'
  desc 'Without policies and procedures in place, the organization will not have the authority to hold personnel accountable for improperly handling or transporting data into the test and development environment. The documents need to include guidance for both physical and electronic data migration.'
  desc 'check', "Review the organization's policies and procedures document to ensure proper handling of data being transported into the test and development environment.  This document must include information for physical and electronic migration of data.

If the organization does not have a policy and procedures document created or available for review, this is a finding."
  desc 'fix', 'Create a policy for, and document the procedure of, proper handling of data transported into the test and development environment.  This document must include information for physical and electronic handling and migration of data.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-49290r2_chk'
  tag severity: 'medium'
  tag gid: 'V-43317'
  tag rid: 'SV-56070r1_rule'
  tag stig_id: 'ENTD0370'
  tag gtitle: 'ENTD0370 - Policy and procedures document not created for proper data handling.'
  tag fix_id: 'F-48944r1_fix'
  tag 'documentable'
end
