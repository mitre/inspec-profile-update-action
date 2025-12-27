control 'SV-51296' do
  title 'Development systems must have HIDS or HIPS installed and configured with up-to-date signatures.'
  desc 'A HIDS or HIPS application is a secondary line of defense behind the antivirus.  The application will monitor all ports and the dynamic state of a development system.  If the application detects irregularities on the system, it will block incoming traffic that may potentially compromise the development system that can lead to a DoS or data theft.'
  desc 'check', "Review the development images to determine whether a HIDS or HIPS application is installed and configured.   If a HIDS or HIPS application is not installed and configured on the development image, this is a finding.  

If there isn't any application development occurring in the zone environment, this requirement is not applicable."
  desc 'fix', 'Install and configure a HIDS or HIPS application on development system images.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46713r3_chk'
  tag severity: 'medium'
  tag gid: 'V-39438'
  tag rid: 'SV-51296r1_rule'
  tag stig_id: 'ENTD0080'
  tag gtitle: 'ENTD0080 - HIDS or HIPS not installed on development system.'
  tag fix_id: 'F-44451r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECID-1, ECSC-1'
end
