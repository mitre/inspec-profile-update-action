control 'SV-32948' do
  title 'Web administration tools must be restricted to the web manager and the web manager’s designees.'
  desc 'All automated information systems are at risk of data loss due to disaster or compromise. Failure to provide adequate protection to the administration tools creates risk of potential theft or damage that may ultimately compromise the mission.  Adequate protection ensures that server administration operates with less risk of losses or operations outages.  The key web service administrative and configuration tools must be accessible only by the authorized web server administrators. All users granted this authority must be documented and approved by the ISSO. Access to the IIS Manager will be limited to authorized users and administrators.'
  desc 'check', 'Determine which tool or control file is used to control the configuration of the web server. 

If the control of the web server is done via control files, verify who has update access to them. If tools are being used to configure the web server, determine who has access to execute the tools.

If accounts other than the SA, the web manager, or the web manager designees have access to the web administration tool or control files, this is a finding.'
  desc 'fix', 'Restrict access to the web administration tool to only the web manager and the web manager’s designees.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-29923r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2248'
  tag rid: 'SV-32948r2_rule'
  tag stig_id: 'WG220 A22'
  tag gtitle: 'WG220'
  tag fix_id: 'F-26807r1_fix'
  tag 'documentable'
  tag responsibility: ['Web Administrator', 'System Administrator']
  tag ia_controls: 'ECCD-1, ECCD-2, ECLP-1'
end
