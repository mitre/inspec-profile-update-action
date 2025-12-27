control 'SV-240949' do
  title 'The vAMI account credentials must protected by site policies.'
  desc 'Application servers provide remote access capability and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. Automated monitoring and control of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by logging connection activities of remote users. Examples of policy requirements include, but are not limited to, authorizing remote access to the information system, limiting access based on authentication credentials, and monitoring for unauthorized access.'
  desc 'check', 'Interview the ISSO and/or the SA.

Determine if access credentials for the vAMI are controlled by a site policy.
 
If a site policy does not exist, or is not being followed, this is a finding.'
  desc 'fix', 'Develop and implement a site procedure to control access credentials for the vAMI.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44182r676012_chk'
  tag severity: 'medium'
  tag gid: 'V-240949'
  tag rid: 'SV-240949r879692_rule'
  tag stig_id: 'VRAU-VA-000385'
  tag gtitle: 'SRG-APP-000315-AS-000094'
  tag fix_id: 'F-44141r676013_fix'
  tag 'documentable'
  tag legacy: ['SV-100891', 'V-90241']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
