control 'SV-239106' do
  title 'The Photon operating system must not have Duplicate User IDs (UIDs).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and provide for non-repudiation.'
  desc 'check', %q(At the command line, execute the following command:

# awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If any lines are returned, this is a finding.)
  desc 'fix', 'Open /etc/passwd with a text editor. 

Configure each user account that has a duplicate UID with a unique UID.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42317r675124_chk'
  tag severity: 'medium'
  tag gid: 'V-239106'
  tag rid: 'SV-239106r675126_rule'
  tag stig_id: 'PHTN-67-000034'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-42276r675125_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
