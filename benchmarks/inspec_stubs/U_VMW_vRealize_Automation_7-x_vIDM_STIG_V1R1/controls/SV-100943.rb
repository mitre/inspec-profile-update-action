control 'SV-100943' do
  title 'vIDM, when installed in a MAC I system, must be in a high-availability (HA) cluster.'
  desc "A MAC I system is a system that handles data vital to the organization's operational readiness or effectiveness of deployed or contingency forces. A MAC I system must maintain the highest level of integrity and availability. By HA clustering the application server, the hosted application and data are given a platform that is load-balanced and provided high-availability."
  desc 'check', "If vRA is not installed in a MAC I system, this is Not Applicable.

Interview the ISSO. Obtain the correct configuration for clustering used by the site.

Review the vRealize Automation appliance's installation, environment, and configuration. Determine if vRA clustering has been correctly implemented.

If vRA is not correctly implementing clustering, this is a finding."
  desc 'fix', 'If vRA is not installed in a MAC I system, this is Not Applicable.

Interview the ISSO. Obtain the correct configuration for clustering used by the site.

Configure vRealize Automation to be in compliance with the clustering design provided by the ISSO.'
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x vIDM'
  tag check_id: 'C-89985r1_chk'
  tag severity: 'high'
  tag gid: 'V-90293'
  tag rid: 'SV-100943r1_rule'
  tag stig_id: 'VRAU-VI-000550'
  tag gtitle: 'SRG-APP-000435-AS-000069'
  tag fix_id: 'F-97035r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
