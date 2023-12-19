control 'SV-240972' do
  title 'vIDM must be configured to provide clustering.'
  desc 'This requirement is dependent upon system MAC and confidentiality. If the system MAC and confidentiality levels do not specify redundancy requirements, this requirement is NA. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. When application failure is encountered, preserving application state facilitates application restart and return to the operational mode of the organization with less disruption of mission/business processes. Clustering of multiple application servers is a common approach to providing fail-safe application availability when system MAC and confidentiality levels require redundancy.'
  desc 'check', "Interview the ISSO. Obtain the correct configuration for clustering used by the site.

Review the vRealize Automation appliance's installation, environment, and configuration. Determine if vRA clustering has been correctly implemented.

If vRA is not correctly implementing clustering, this is a finding."
  desc 'fix', 'Interview the ISSO. Obtain the correct configuration for clustering used by the site.

Configure vRealize Automation to be in compliance with the clustering design provided by the ISSO.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vIDM'
  tag check_id: 'C-44205r676175_chk'
  tag severity: 'medium'
  tag gid: 'V-240972'
  tag rid: 'SV-240972r879640_rule'
  tag stig_id: 'VRAU-VI-000315'
  tag gtitle: 'SRG-APP-000225-AS-000154'
  tag fix_id: 'F-44164r676176_fix'
  tag 'documentable'
  tag legacy: ['SV-100939', 'V-90289']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
